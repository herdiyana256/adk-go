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

// Package eventarc provides a sublauncher that adds Eventarc trigger capabilities to ADK web server.
package eventarc

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

type eventarcConfig struct {
	pathPrefix                 string
	triggerMaxRetries          int
	triggerBaseDelay           time.Duration
	triggerMaxDelay            time.Duration
	triggerMaxRuns             int
	triggerOIDCAudience        string
	triggerOIDCServiceAccounts string
}

// Config configures the Eventarc sublauncher beyond its command-line flags.
type Config struct {
	// Authenticator, when non-nil, gates the Eventarc trigger endpoint and
	// takes precedence over the -trigger_oidc_* flags. Supply it to verify
	// inbound deliveries with a scheme of your own instead of the built-in
	// Google OIDC one.
	//
	// It is deliberately separate from launcher.Config.Authenticator, which
	// gates the REST API. A trigger endpoint receives Eventarc and Pub/Sub push
	// deliveries, not the browser and API-key traffic the REST authenticator is
	// chosen for, so reusing that one here would gate deliveries with the wrong
	// credential scheme. The two are configured independently on purpose.
	Authenticator authn.Authenticator
}

type eventarcLauncher struct {
	flags  *flag.FlagSet
	config *eventarcConfig

	// authOverride is an Authenticator supplied through NewLauncherWithConfig.
	// When non-nil it wins over the -trigger_oidc_* flags. Nil otherwise.
	authOverride authn.Authenticator

	// authenticator is the resolved gate for the trigger endpoint, set by
	// [eventarcLauncher.Parse]: authOverride when non-nil, otherwise one built
	// from the flags, otherwise nil for an open endpoint. Both SetupSubrouters
	// and UserMessage read this one field, so the protection the endpoint
	// enforces and the message describing it cannot drift apart.
	authenticator authn.Authenticator
}

// NewLauncher creates a new eventarc launcher. It extends Web launcher.
func NewLauncher() web.Sublauncher {
	return NewLauncherWithConfig(Config{})
}

// NewLauncherWithConfig creates an eventarc launcher with programmatic
// configuration. A non-nil cfg.Authenticator gates the trigger endpoint and
// takes precedence over the -trigger_oidc_* flags.
func NewLauncherWithConfig(cfg Config) web.Sublauncher {
	config := &eventarcConfig{}

	fs := flag.NewFlagSet("eventarc", flag.ContinueOnError)
	fs.StringVar(&config.pathPrefix, "path_prefix", "/api", "Path prefix for the Eventarc trigger endpoint. Default is '/api'.")
	fs.IntVar(&config.triggerMaxRetries, "trigger_max_retries", 3, "Maximum retries for HTTP 429 errors from triggers")
	fs.DurationVar(&config.triggerBaseDelay, "trigger_base_delay", 1*time.Second, "Base delay for trigger retry exponential backoff")
	fs.DurationVar(&config.triggerMaxDelay, "trigger_max_delay", 10*time.Second, "Maximum delay for trigger retry exponential backoff")
	fs.IntVar(&config.triggerMaxRuns, "trigger_max_concurrent_runs", 100, "Maximum concurrent trigger runs")
	fs.StringVar(&config.triggerOIDCAudience, "trigger_oidc_audience", "", "If set, require a Google-signed OIDC token whose audience matches this value on the trigger endpoint. Enabling verification also requires -trigger_oidc_service_accounts.")
	fs.StringVar(&config.triggerOIDCServiceAccounts, "trigger_oidc_service_accounts", "", "Comma-separated service account emails permitted to call the trigger endpoint; required whenever -trigger_oidc_audience is set. A token minted for manual testing must be requested with includeEmail:true so it carries the email this checks against.")

	return &eventarcLauncher{
		config:       config,
		flags:        fs,
		authOverride: cfg.Authenticator,
	}
}

// Keyword implements web.Sublauncher. Returns the command-line keyword for eventarc launcher.
func (e *eventarcLauncher) Keyword() string {
	return "eventarc"
}

// Parse parses the command-line arguments for the eventarc launcher.
func (e *eventarcLauncher) Parse(args []string) ([]string, error) {
	err := e.flags.Parse(args)
	if err != nil || !e.flags.Parsed() {
		return nil, fmt.Errorf("failed to parse eventarc flags: %v", err)
	}
	if e.config.triggerMaxRetries <= 0 {
		return nil, fmt.Errorf("trigger_max_retries must be > 0")
	}
	if e.config.triggerBaseDelay < 0 {
		return nil, fmt.Errorf("trigger_base_delay must be >= 0")
	}
	if e.config.triggerMaxDelay <= 0 {
		return nil, fmt.Errorf("trigger_max_delay must be > 0")
	}
	if e.config.triggerMaxRuns <= 0 {
		return nil, fmt.Errorf("trigger_max_concurrent_runs must be > 0")
	}

	prefix := e.config.pathPrefix
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	e.config.pathPrefix = strings.TrimSuffix(prefix, "/")

	// Resolve the endpoint's gate now, while an error can still stop startup
	// rather than surface as a crash-looping revision, and store it once so
	// SetupSubrouters and UserMessage read the same decision.
	auth, err := e.resolveAuthenticator()
	if err != nil {
		return nil, err
	}
	e.authenticator = auth

	return e.flags.Args(), nil
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
func (e *eventarcLauncher) resolveAuthenticator() (authn.Authenticator, error) {
	audience := strings.TrimSpace(e.config.triggerOIDCAudience)
	accounts := splitServiceAccounts(e.config.triggerOIDCServiceAccounts)

	if e.authOverride != nil {
		if audience != "" || len(accounts) > 0 {
			log.Print("adk: eventarc: an Authenticator was supplied programmatically, so the " +
				"-trigger_oidc_* flags are ignored.")
		}
		return e.authOverride, nil
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

// CommandLineSyntax returns the command-line syntax for the eventarc launcher.
func (e *eventarcLauncher) CommandLineSyntax() string {
	return util.FormatFlagUsage(e.flags)
}

// SimpleDescription implements web.Sublauncher.
func (e *eventarcLauncher) SimpleDescription() string {
	return "starts ADK Eventarc trigger endpoint server"
}

// SetupSubrouters adds the Eventarc trigger endpoint to the parent router.
func (e *eventarcLauncher) SetupSubrouters(router *mux.Router, config *launcher.Config) error {
	triggerConfig := triggers.TriggerConfig{
		MaxRetries:        e.config.triggerMaxRetries,
		BaseDelay:         e.config.triggerBaseDelay,
		MaxDelay:          e.config.triggerMaxDelay,
		MaxConcurrentRuns: e.config.triggerMaxRuns,
	}

	controller, err := triggers.NewEventarcControllerWithConfig(triggers.ControllerConfig{
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
	if e.config.pathPrefix != "" && e.config.pathPrefix != "/" {
		subrouter = router.PathPrefix(e.config.pathPrefix).Subrouter()
	}

	// Gate only the trigger route. The subrouter can be the shared parent
	// router when no path prefix is set, so wrapping the single handler rather
	// than calling subrouter.Use keeps the middleware off every other
	// sublauncher's routes. A nil authenticator wraps to a pass-through.
	var handler http.Handler = http.HandlerFunc(controller.EventarcTriggerHandler)
	if e.authenticator != nil {
		handler = authn.Middleware(e.authenticator)(handler)
	}
	subrouter.Handle("/apps/{app_name}/trigger/eventarc", handler).Methods(http.MethodPost)
	return nil
}

// UserMessage implements web.Sublauncher.
func (e *eventarcLauncher) UserMessage(webURL string, printer func(v ...any)) {
	printer(fmt.Sprintf("       eventarc: Eventarc trigger endpoint is available at %s%s/apps/{app_name}/trigger/eventarc", webURL, e.config.pathPrefix))
	// Read the same field the route is gated with, so an operator is never told
	// the endpoint is protected when it is not, nor the reverse.
	if e.authenticator != nil {
		printer("       eventarc: OIDC verification is enabled on the Eventarc trigger endpoint.")
	} else {
		printer("       eventarc: OIDC verification is DISABLED; the Eventarc trigger endpoint accepts unauthenticated requests.")
	}
}
