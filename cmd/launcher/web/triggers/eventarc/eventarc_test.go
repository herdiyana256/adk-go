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

package eventarc

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"google.golang.org/adk/v2/cmd/launcher"
	"google.golang.org/adk/v2/server/authn"
)

func TestSetupSubrouters(t *testing.T) {
	l := NewLauncher().(*eventarcLauncher)
	if _, err := l.Parse([]string{"-path_prefix=/api"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	router := mux.NewRouter()
	if err := l.SetupSubrouters(router, &launcher.Config{}); err != nil {
		t.Fatalf("SetupSubrouters() failed: %v", err)
	}

	// Verify route is registered.
	req := httptest.NewRequest(http.MethodPost, "/api/apps/my-app/trigger/eventarc", nil)
	var match mux.RouteMatch
	if !router.Match(req, &match) {
		t.Errorf("SetupSubrouters() did not register expected route")
	}
}

// TestParseResolvesOIDC pins the flag validation and, with it, that the
// allow-list is mandatory whenever an audience is set. Enabling verification
// with an audience alone is refused, so a deployment cannot end up accepting any
// caller that holds a Google-signed token for the audience.
func TestParseResolvesOIDC(t *testing.T) {
	const (
		aud     = "https://eventarc.example/adk"
		account = "svc@proj.iam.gserviceaccount.com"
	)
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		wantAuth bool // whether an authenticator must have been resolved
	}{
		{
			name:     "no oidc flags leaves the endpoint open",
			args:     nil,
			wantAuth: false,
		},
		{
			name:     "audience and service accounts enable verification",
			args:     []string{"-trigger_oidc_audience=" + aud, "-trigger_oidc_service_accounts=" + account},
			wantAuth: true,
		},
		{
			name:    "audience without service accounts is rejected",
			args:    []string{"-trigger_oidc_audience=" + aud},
			wantErr: true,
		},
		{
			name:    "service accounts without audience is rejected",
			args:    []string{"-trigger_oidc_service_accounts=" + account},
			wantErr: true,
		},
		{
			name:     "blank service-account entries are dropped",
			args:     []string{"-trigger_oidc_audience=" + aud, "-trigger_oidc_service_accounts= " + account + " , "},
			wantAuth: true,
		},
		{
			name:    "only blank service-account entries is treated as empty",
			args:    []string{"-trigger_oidc_audience=" + aud, "-trigger_oidc_service_accounts= , "},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLauncher().(*eventarcLauncher)
			_, err := l.Parse(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got := l.authenticator != nil; got != tt.wantAuth {
				t.Errorf("Parse() resolved authenticator present = %v, want %v", got, tt.wantAuth)
			}
		})
	}
}

// TestSetupSubroutersWiresOIDC drives a real router and observes a 401 on the
// trigger route with no credential. It goes through SetupSubrouters rather than
// reading l.authenticator, so it fails if a change stops SetupSubrouters from
// wrapping the handler with the gate the flags asked for.
func TestSetupSubroutersWiresOIDC(t *testing.T) {
	l := NewLauncher().(*eventarcLauncher)
	if _, err := l.Parse([]string{
		"-trigger_oidc_audience=https://eventarc.example/adk",
		"-trigger_oidc_service_accounts=svc@proj.iam.gserviceaccount.com",
	}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	router := mux.NewRouter()
	if err := l.SetupSubrouters(router, &launcher.Config{}); err != nil {
		t.Fatalf("SetupSubrouters() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/apps/my-app/trigger/eventarc", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-credential request status = %d, want %d; the OIDC gate did not reach the route", rec.Code, http.StatusUnauthorized)
	}
}

// forbiddingAuth is a stand-in Authenticator that refuses every request with a
// 403, distinguishable from the built-in Google OIDC gate's 401 for a request
// carrying no bearer token.
type forbiddingAuth struct{}

func (forbiddingAuth) Authenticate(*http.Request) (*authn.Caller, error) {
	return nil, fmt.Errorf("stub refuses: %w", authn.ErrForbidden)
}

// TestConfigAuthenticatorWins checks that a programmatic Authenticator takes
// precedence over the -trigger_oidc_* flags, and reaches the route. Both flags
// are also set, so a 401 would mean the flags won; the 403 can only come from
// the override.
func TestConfigAuthenticatorWins(t *testing.T) {
	l := NewLauncherWithConfig(Config{Authenticator: forbiddingAuth{}}).(*eventarcLauncher)
	if _, err := l.Parse([]string{
		"-trigger_oidc_audience=https://eventarc.example/adk",
		"-trigger_oidc_service_accounts=svc@proj.iam.gserviceaccount.com",
	}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	router := mux.NewRouter()
	if err := l.SetupSubrouters(router, &launcher.Config{}); err != nil {
		t.Fatalf("SetupSubrouters() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/apps/my-app/trigger/eventarc", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; the programmatic Authenticator did not win over the flags", rec.Code, http.StatusForbidden)
	}
}

// TestConfigAuthenticatorSkipsFlagValidation confirms the override is exempt
// from the audience-requires-allow-list rule: an embedder supplying its own gate
// has already decided how callers are identified.
func TestConfigAuthenticatorSkipsFlagValidation(t *testing.T) {
	l := NewLauncherWithConfig(Config{Authenticator: forbiddingAuth{}}).(*eventarcLauncher)
	if _, err := l.Parse(nil); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if l.authenticator == nil {
		t.Error("Parse() resolved a nil authenticator, want the programmatic override")
	}
}
