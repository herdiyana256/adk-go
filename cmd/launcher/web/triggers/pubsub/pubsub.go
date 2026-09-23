// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pubsub provides a sublauncher that adds PubSub trigger capabilities to ADK web server.
package pubsub

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"google.golang.org/adk/v2/cmd/launcher"
	"google.golang.org/adk/v2/cmd/launcher/web"
	"google.golang.org/adk/v2/internal/cli/util"
	"google.golang.org/adk/v2/server/adkrest/controllers/triggers"
	"google.golang.org/adk/v2/server/authn"
)

type pubsubConfig struct {
	pathPrefix                 string
	triggerMaxRetries          int
	triggerBaseDelay           time.Duration
	triggerMaxDelay            time.Duration
	triggerMaxRuns             int
	triggerOIDCAudience        string
	triggerOIDCServiceAccounts string
}

// Config configures the Pub/Sub sublauncher beyond its command-line flags.
type Config struct {
	// Authenticator, when non-nil, gates the Pub/Sub trigger endpoint and takes
	// precedence over the -trigger_oidc_* flags. Supply it to verify inbound
	// deliveries with a scheme of your own instead of the built-in Google OIDC
	// one.
	//
	// It is deliberately separate from launcher.Config.Authenticator, which
	// gates the REST API. A trigger endpoint receives Pub/Sub push and Eventarc
	// deliveries, not the browser and API-key traffic the REST authenticator is
	// chosen for, so reusing that one here would gate deliveries with the wrong
	// credential scheme. The two are configured independently on purpose.
	Authenticator authn.Authenticator
}

type pubsubLauncher struct {
	flags  *flag.FlagSet
	config *pubsubConfig

	// authOverride is an Authenticator supplied through NewLauncherWithConfig.
	// When non-nil it wins over the -trigger_oidc_* flags. Nil otherwise.
	authOverride authn.Authenticator

	// authenticator is the resolved gate for the trigger endpoint, set by
	// [pubsubLauncher.Parse]: authOverride when non-nil, otherwise one built
	// from the flags, otherwise nil for an open endpoint. Both SetupSubrouters
	// and UserMessage read this one field, so the protection the endpoint
	// enforces and the message describing it cannot drift apart.
	authenticator authn.Authenticator
}

// NewLauncher creates a new pubsub launcher. It extends Web launcher.
func NewLauncher() web.Sublauncher {
	return NewLauncherWithConfig(Config{})
}

// NewLauncherWithConfig creates a pubsub launcher with programmatic
// configuration. A non-nil cfg.Authenticator gates the trigger endpoint and
// takes precedence over the -trigger_oidc_* flags.
func NewLauncherWithConfig(cfg Config) web.Sublauncher {
	config := &pubsubConfig{}

	fs := flag.NewFlagSet("pubsub", flag.ContinueOnError)
	fs.StringVar(&config.pathPrefix, "path_prefix", "/api", "Path prefix for the PubSub trigger endpoint. Default is '/api'.")
	fs.IntVar(&config.triggerMaxRetries, "trigger_max_retries", 3, "Maximum retries for HTTP 429 errors from triggers")
	fs.DurationVar(&config.triggerBaseDelay, "trigger_base_delay", 1*time.Second, "Base delay for trigger retry exponential backoff")
	fs.DurationVar(&config.triggerMaxDelay, "trigger_max_delay", 10*time.Second, "Maximum delay for trigger retry exponential backoff")
	fs.IntVar(&config.triggerMaxRuns, "trigger_max_concurrent_runs", 100, "Maximum concurrent trigger runs")
	fs.StringVar(&config.triggerOIDCAudience, "trigger_oidc_audience", "", "If set, require a Google-signed OIDC token whose audience matches this value on the trigger endpoint. Enabling verification also requires -trigger_oidc_service_accounts.")
	fs.StringVar(&config.triggerOIDCServiceAccounts, "trigger_oidc_service_accounts", "", "Comma-separated service account emails permitted to call the trigger endpoint; required whenever -trigger_oidc_audience is set. A token minted for manual testing must be requested with includeEmail:true so it carries the email this checks against.")

	return &pubsubLauncher{
		config:       config,
		flags:        fs,
		authOverride: cfg.Authenticator,
	}
}

// Keyword implements web.Sublauncher. Returns the command-line keyword for pubsub launcher.
func (p *pubsubLauncher) Keyword() string {
	return "pubsub"
}

// Parse parses the command-line arguments for the pubsub launcher.
func (p *pubsubLauncher) Parse(args []string) ([]string, error) {
	err := p.flags.Parse(args)
	if err != nil || !p.flags.Parsed() {
		return nil, fmt.Errorf("failed to parse pubsub flags: %v", err)
	}
	if p.config.triggerMaxRetries <= 0 {
		return nil, fmt.Errorf("trigger_max_retries must be > 0")
	}
	if p.config.triggerBaseDelay < 0 {
		return nil, fmt.Errorf("trigger_base_delay must be >= 0")
	}
	if p.config.triggerMaxDelay <= 0 {
		return nil, fmt.Errorf("trigger_max_delay must be > 0")
	}
	if p.config.triggerMaxRuns <= 0 {
		return nil, fmt.Errorf("trigger_max_concurrent_runs must be > 0")
	}

	prefix := p.config.pathPrefix
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	p.config.pathPrefix = strings.TrimSuffix(prefix, "/")

	// Resolve the endpoint's gate now, while an error can still stop startup
	// rather than surface as a crash-looping revision, and store it once so
	// SetupSubrouters and UserMessage read the same decision.
	auth, err := p.resolveAuthenticator()
	if err != nil {
		return nil, err
	}
	p.authenticator = auth

	return p.flags.Args(), nil
}

// resolveAuthenticator decides how the trigger endpoint is gated: the
// programmatic override first, the -trigger_oidc_* flags second. It is the one
// place either input is read, so the gate SetupSubrouters wires and the status
// UserMessage prints cannot describe different protection than is enforced.
//
// Audience alone is refused. A verified audience proves only that some
// Google-signed token for that string was presented, not which principal sent
// it, because the audience is chosen by whoever mints the token. Requiring the
// allow-list keeps a caller from minting a token for the audience with a
// service account of its own and being accepted.
func (p *pubsubLauncher) resolveAuthenticator() (authn.Authenticator, error) {
	audience := strings.TrimSpace(p.config.triggerOIDCAudience)
	accounts := splitServiceAccounts(p.config.triggerOIDCServiceAccounts)

	if p.authOverride != nil {
		if audience != "" || len(accounts) > 0 {
			log.Print("adk: pubsub: an Authenticator was supplied programmatically, so the " +
				"-trigger_oidc_* flags are ignored.")
		}
		return p.authOverride, nil
	}

	switch {
	case audience == "" && len(accounts) == 0:
		// A trigger with no service account attaches no token, so an open
		// endpoint is the correct default for that deployment.
		return nil, nil
	case audience == "":
		return nil, fmt.Errorf("-trigger_oidc_service_accounts requires -trigger_oidc_audience")
	case len(accounts) == 0:
		return nil, fmt.Errorf("-trigger_oidc_audience requires -trigger_oidc_service_accounts")
	}
	return authn.NewGoogleOIDC(audience, accounts)
}

// splitServiceAccounts turns the comma-separated
// -trigger_oidc_service_accounts value into a list, dropping empty entries so a
// trailing comma or stray space cannot become an unmatchable "" in the
// allow-list.
func splitServiceAccounts(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// CommandLineSyntax returns the command-line syntax for the pubsub launcher.
func (p *pubsubLauncher) CommandLineSyntax() string {
	return util.FormatFlagUsage(p.flags)
}

// SimpleDescription implements web.Sublauncher.
func (p *pubsubLauncher) SimpleDescription() string {
	return "starts ADK PubSub trigger endpoint server"
}

// SetupSubrouters adds the PubSub trigger endpoint to the parent router.
func (p *pubsubLauncher) SetupSubrouters(router *mux.Router, config *launcher.Config) error {
	triggerConfig := triggers.TriggerConfig{
		MaxRetries:        p.config.triggerMaxRetries,
		BaseDelay:         p.config.triggerBaseDelay,
		MaxDelay:          p.config.triggerMaxDelay,
		MaxConcurrentRuns: p.config.triggerMaxRuns,
	}

	controller, err := triggers.NewPubSubControllerWithConfig(triggers.ControllerConfig{
		SessionService:  config.SessionService,
		AgentLoader:     config.AgentLoader,
		MemoryService:   config.MemoryService,
		ArtifactService: config.ArtifactService,
		PluginConfig:    config.PluginConfig,
		TriggerConfig:   triggerConfig,
		Compaction:      config.Compaction,
	})
	if err != nil {
		return err
	}

	subrouter := router
	if p.config.pathPrefix != "" && p.config.pathPrefix != "/" {
		subrouter = router.PathPrefix(p.config.pathPrefix).Subrouter()
	}

	// Gate only the trigger route. The subrouter can be the shared parent
	// router when no path prefix is set, so wrapping the single handler rather
	// than calling subrouter.Use keeps the middleware off every other
	// sublauncher's routes. A nil authenticator wraps to a pass-through.
	var handler http.Handler = http.HandlerFunc(controller.PubSubTriggerHandler)
	if p.authenticator != nil {
		handler = authn.Middleware(p.authenticator)(handler)
	}
	subrouter.Handle("/apps/{app_name}/trigger/pubsub", handler).Methods(http.MethodPost)
	return nil
}

// UserMessage implements web.Sublauncher.
func (p *pubsubLauncher) UserMessage(webURL string, printer func(v ...any)) {
	printer(fmt.Sprintf("       pubsub:  PubSub trigger endpoint is available at %s%s/apps/{app_name}/trigger/pubsub", webURL, p.config.pathPrefix))
	// Read the same field the route is gated with, so an operator is never told
	// the endpoint is protected when it is not, nor the reverse.
	if p.authenticator != nil {
		printer("       pubsub:  OIDC verification is enabled on the PubSub trigger endpoint.")
	} else {
		printer("       pubsub:  OIDC verification is DISABLED; the PubSub trigger endpoint accepts unauthenticated requests.")
	}
}
