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

package cloudrun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestWriteTriggerArgs(t *testing.T) {
	tests := []struct {
		name    string
		cfg     triggerConfigFlags
		want    []string
		notWant []string
	}{
		{
			name: "no oidc flags emits only the retry knobs",
			cfg:  triggerConfigFlags{maxRetries: 3, baseDelay: time.Second, maxDelay: 10 * time.Second, maxRuns: 100},
			want: []string{`"--trigger_max_retries", "3"`, `"--trigger_max_concurrent_runs", "100"`},
			notWant: []string{
				`--trigger_oidc_audience`,
				`--trigger_oidc_service_accounts`,
			},
		},
		{
			name: "both oidc values are emitted",
			cfg: triggerConfigFlags{
				maxRetries: 3, baseDelay: time.Second, maxDelay: 10 * time.Second, maxRuns: 100,
				oidcAudience:        "https://x.example/adk",
				oidcServiceAccounts: "svc@proj.iam.gserviceaccount.com",
			},
			want: []string{
				`"--trigger_oidc_audience", "https://x.example/adk"`,
				`"--trigger_oidc_service_accounts", "svc@proj.iam.gserviceaccount.com"`,
			},
		},
		{
			name: "whitespace-only oidc values are treated as absent",
			cfg: triggerConfigFlags{
				maxRetries: 3, baseDelay: time.Second, maxDelay: 10 * time.Second, maxRuns: 100,
				oidcAudience:        "   ",
				oidcServiceAccounts: "\t",
			},
			notWant: []string{`--trigger_oidc_audience`, `--trigger_oidc_service_accounts`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b strings.Builder
			writeTriggerArgs(&b, tt.cfg)
			got := b.String()
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("writeTriggerArgs() = %q, want it to contain %q", got, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Errorf("writeTriggerArgs() = %q, want it not to contain %q", got, notWant)
				}
			}
		})
	}
}

// The CMD line is a JSON array, so a flag value carrying a quote must not be
// able to close the string it sits in and add arguments of its own. Both
// operator-supplied fields go through the same encoding, so both are exercised
// here; the whole array is round-tripped through json.Unmarshal to prove the
// hostile input landed as a single argument value rather than as new tokens.
func TestWriteTriggerArgsEscapesFlagValues(t *testing.T) {
	const (
		hostileAud     = `x", "--evil-audience-arg", "y`
		hostileAccount = `a@b.example", "--evil-account-arg", "c`
	)
	cfg := triggerConfigFlags{
		maxRetries: 3, baseDelay: time.Second, maxDelay: 10 * time.Second, maxRuns: 100,
		oidcAudience:        hostileAud,
		oidcServiceAccounts: hostileAccount,
	}

	var b strings.Builder
	// A minimal well-formed array around the fragment, so json.Unmarshal has a
	// complete document to parse.
	b.WriteString(`["cmd"`)
	writeTriggerArgs(&b, cfg)
	b.WriteString(`]`)

	var args []string
	if err := json.Unmarshal([]byte(b.String()), &args); err != nil {
		t.Fatalf("emitted array is not valid JSON: %v\narray: %s", err, b.String())
	}

	// The two injected flag names must never appear as their own array
	// elements; if the encoding failed they would.
	for _, injected := range []string{"--evil-audience-arg", "--evil-account-arg"} {
		if slices.Contains(args, injected) {
			t.Errorf("hostile value broke out into a separate argument %q; args = %q", injected, args)
		}
	}
	// The hostile values must survive verbatim as the single argument after
	// their flag.
	if got := valueAfter(args, "--trigger_oidc_audience"); got != hostileAud {
		t.Errorf("audience argument = %q, want %q", got, hostileAud)
	}
	if got := valueAfter(args, "--trigger_oidc_service_accounts"); got != hostileAccount {
		t.Errorf("service-accounts argument = %q, want %q", got, hostileAccount)
	}
}

// TestPrepareDockerfileRoutesAudienceToItsOwnTrigger is the test the call sites
// need: it runs the real prepareDockerfile with both triggers enabled and a
// distinct audience each, then checks each audience lands in its own trigger's
// section of the emitted CMD. Swapping the two writeTriggerArgs arguments — the
// mistake nothing else catches, because both call sites compile either way —
// puts pubsub's audience in eventarc's section and fails this.
func TestPrepareDockerfileRoutesAudienceToItsOwnTrigger(t *testing.T) {
	const (
		pubsubAud   = "https://pubsub.example/adk"
		eventarcAud = "https://eventarc.example/adk"
		account     = "svc@proj.iam.gserviceaccount.com"
	)

	dir := t.TempDir()
	f := &deployCloudRunFlags{}
	f.build.execFile = "server"
	f.build.dockerfileBuildPath = filepath.Join(dir, "Dockerfile")
	f.cloudRun.serverPort = 8080
	f.proxy.port = 9090
	f.cloudRun.pubsub = true
	f.cloudRun.pubsubTrigger = triggerConfigFlags{
		maxRetries: 3, baseDelay: time.Second, maxDelay: 10 * time.Second, maxRuns: 100,
		oidcAudience: pubsubAud, oidcServiceAccounts: account,
	}
	f.cloudRun.eventarc = true
	f.cloudRun.eventarcTrigger = triggerConfigFlags{
		maxRetries: 3, baseDelay: time.Second, maxDelay: 10 * time.Second, maxRuns: 100,
		oidcAudience: eventarcAud, oidcServiceAccounts: account,
	}

	if err := f.prepareDockerfile(); err != nil {
		t.Fatalf("prepareDockerfile() error = %v", err)
	}

	args := cmdArray(t, f.build.dockerfileBuildPath)

	pubsubIdx := slices.Index(args, "pubsub")
	eventarcIdx := slices.Index(args, "eventarc")
	if pubsubIdx < 0 || eventarcIdx < 0 || pubsubIdx >= eventarcIdx {
		t.Fatalf("expected a pubsub section before an eventarc section; args = %q", args)
	}
	pubsubSection := args[pubsubIdx:eventarcIdx]
	eventarcSection := args[eventarcIdx:]

	if got := valueAfter(pubsubSection, "--trigger_oidc_audience"); got != pubsubAud {
		t.Errorf("pubsub section audience = %q, want %q; args = %q", got, pubsubAud, args)
	}
	if got := valueAfter(eventarcSection, "--trigger_oidc_audience"); got != eventarcAud {
		t.Errorf("eventarc section audience = %q, want %q; args = %q", got, eventarcAud, args)
	}
}

func TestValidateTriggerOIDC(t *testing.T) {
	const (
		aud     = "https://x.example/adk"
		account = "svc@proj.iam.gserviceaccount.com"
	)
	tests := []struct {
		name    string
		cfg     triggerConfigFlags
		wantErr bool
	}{
		{name: "neither set", cfg: triggerConfigFlags{}},
		{name: "both set", cfg: triggerConfigFlags{oidcAudience: aud, oidcServiceAccounts: account}},
		{name: "audience only", cfg: triggerConfigFlags{oidcAudience: aud}, wantErr: true},
		{name: "accounts only", cfg: triggerConfigFlags{oidcServiceAccounts: account}, wantErr: true},
		{name: "whitespace audience with real accounts", cfg: triggerConfigFlags{oidcAudience: "  ", oidcServiceAccounts: account}, wantErr: true},
		{name: "quote in audience is rejected", cfg: triggerConfigFlags{oidcAudience: `x"y`, oidcServiceAccounts: account}, wantErr: true},
		{name: "quote in accounts is rejected", cfg: triggerConfigFlags{oidcAudience: aud, oidcServiceAccounts: `a"b`}, wantErr: true},
		{name: "invalid utf-8 in audience is rejected", cfg: triggerConfigFlags{oidcAudience: "x\xff", oidcServiceAccounts: account}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateTriggerOIDC(tt.cfg, "pubsub"); (err != nil) != tt.wantErr {
				t.Errorf("validateTriggerOIDC() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestComputeFlagsChecksBothTriggersOIDC proves the validateTriggerOIDC calls
// are wired into computeFlags for each trigger, not merely defined: deleting
// either call would let an audience-only trigger deploy, and that trigger would
// crash-loop on startup. Both checks run before any filesystem work, so a bare
// flags struct is enough to reach them.
func TestComputeFlagsChecksBothTriggersOIDC(t *testing.T) {
	for _, prefix := range []string{"pubsub", "eventarc"} {
		t.Run(prefix, func(t *testing.T) {
			f := &deployCloudRunFlags{}
			if prefix == "pubsub" {
				f.cloudRun.pubsubTrigger.oidcAudience = "https://x.example/adk"
			} else {
				f.cloudRun.eventarcTrigger.oidcAudience = "https://x.example/adk"
			}
			err := f.computeFlags()
			if err == nil {
				t.Fatalf("computeFlags() error = nil, want an error for an audience-only %s trigger", prefix)
			}
			if !strings.Contains(err.Error(), prefix+"_oidc_service_accounts") {
				t.Errorf("computeFlags() error = %v, want it to name --%s_oidc_service_accounts", err, prefix)
			}
		})
	}
}

// valueAfter returns the element immediately following the first occurrence of
// flag in args, or "" if flag is absent or last.
func valueAfter(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

// cmdArray reads the Dockerfile at path, finds its CMD instruction and returns
// the exec-form array parsed as strings.
func cmdArray(t *testing.T, path string) []string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading Dockerfile: %v", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "CMD ")
		if !ok {
			continue
		}
		var args []string
		if err := json.Unmarshal([]byte(rest), &args); err != nil {
			t.Fatalf("CMD line is not a valid JSON array: %v\nline: %s", err, rest)
		}
		return args
	}
	t.Fatalf("no CMD instruction found in Dockerfile:\n%s", content)
	return nil
}
