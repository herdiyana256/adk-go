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

package authn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"

	"google.golang.org/api/idtoken"
)

// googleOIDC authenticates the Google-signed OIDC bearer token that a Pub/Sub
// push subscription or an Eventarc trigger attaches when it is configured with
// a service account.
type googleOIDC struct {
	audience               string
	allowedServiceAccounts []string

	// validate defaults to idtoken.Validate when nil. A field rather than a
	// package variable, so parallel tests can install their own fake without
	// racing and without a live call to Google's certificate endpoint.
	validate tokenValidator
}

// tokenValidator matches the signature of [idtoken.Validate], which is what
// production uses.
type tokenValidator func(ctx context.Context, idToken, audience string) (*idtoken.Payload, error)

// googleIssuers are the two spellings Google uses in iss. idtoken.Validate
// parses the claim but leaves checking it to the caller.
var googleIssuers = []string{"accounts.google.com", "https://accounts.google.com"}

// NewGoogleOIDC returns an [Authenticator] requiring a Google-signed OIDC
// bearer token issued for audience, verified with [idtoken.Validate].
//
// An empty audience is rejected rather than treated as "verify nothing": leave
// the [Authenticator] unset, or use [NewNoop], to run without authentication.
//
// The audience alone does not identify the caller, because it is chosen freely
// by whoever mints the token. Any principal that can call
// iam.serviceAccounts.getOpenIdToken on a service account of its own can get a
// Google-signed token for it. A non-empty allowedServiceAccounts additionally
// requires a verified email claim matching one of the listed addresses, the
// identity the subscription or trigger actually delivers as. Pass nil to accept
// any principal holding a token for the audience.
//
// This mirrors GoogleOidcVerifier(audience, allowed_emails) in adk-python, with
// one deliberate difference: adk-python reports every trigger-auth failure as a
// single 401, whereas here a token that verifies but names a principal outside
// allowedServiceAccounts is refused with [ErrForbidden], a 403. Separating the
// two lets an operator distinguish a caller that presented no valid token from
// one that presented a valid token for an identity the allow-list does not
// name; the response body stays uniform either way, so it never names the
// refused principal nor lists the permitted ones, and the distinction is
// carried by the status alone.
func NewGoogleOIDC(audience string, allowedServiceAccounts []string) (Authenticator, error) {
	if audience == "" {
		return nil, errors.New("authn: NewGoogleOIDC requires an audience")
	}
	return &googleOIDC{
		audience: audience,
		// Copied so a caller mutating its own slice later cannot change what a
		// running authenticator enforces.
		allowedServiceAccounts: slices.Clone(allowedServiceAccounts),
	}, nil
}

// Authenticate implements [Authenticator].
//
// A missing, malformed or unverifiable credential wraps [ErrUnauthenticated],
// so [Middleware] answers 401. A token that verifies but names a principal the
// allow-list does not permit wraps [ErrForbidden] instead, so [Middleware]
// answers 403: the credential was fine, the identity is what is refused.
func (g *googleOIDC) Authenticate(r *http.Request) (*Caller, error) {
	token, err := bearerToken(r.Header.Values("Authorization"))
	if err != nil {
		return nil, deny(err)
	}

	validate := g.validate
	if validate == nil {
		validate = idtoken.Validate
	}
	payload, err := validate(r.Context(), token, g.audience)
	if err != nil {
		return nil, deny(fmt.Errorf("invalid identity token: %w", err))
	}
	if payload == nil {
		return nil, deny(errors.New("identity token verified with no payload"))
	}
	if !slices.Contains(googleIssuers, payload.Issuer) {
		return nil, deny(fmt.Errorf("untrusted issuer %q", payload.Issuer))
	}

	email, _ := payload.Claims["email"].(string)
	// A non-boolean email_verified fails this assertion and so fails closed.
	emailVerified, _ := payload.Claims["email_verified"].(bool)

	// getOpenIdToken defaults includeEmail to false, so a valid token may carry
	// no email at all. That has to miss the pin rather than skip it.
	if len(g.allowedServiceAccounts) > 0 &&
		(email == "" || !emailVerified || !slices.Contains(g.allowedServiceAccounts, email)) {
		return nil, forbid(fmt.Errorf("principal %q (verified=%t) is not an allowed service account", email, emailVerified))
	}

	// sub identifies the principal on a token minted without includeEmail.
	userID := payload.Subject
	if userID == "" {
		userID = email
	}
	if userID == "" {
		return nil, deny(errors.New("identity token carries neither a subject nor an email claim"))
	}

	claims := map[string]any{"aud": payload.Audience}
	if email != "" {
		claims["email"] = email
		claims["email_verified"] = emailVerified
	}
	return &Caller{UserID: userID, Claims: claims}, nil
}

// deny logs the reason and returns it as a credential problem (a 401). The
// reason stays server-side, so a caller cannot tell an expired token from an
// audience mismatch, nor from an untrusted issuer.
func deny(err error) error {
	log.Printf("adk: authn: rejected an OIDC-authenticated request: %v", err)
	return fmt.Errorf("%w: %w", ErrUnauthenticated, err)
}

// forbid logs the reason and returns it as an authorization problem (a 403):
// the token verified, but the principal it named is outside the allow-list. The
// reason stays server-side, so the uniform response body never names the
// refused principal nor distinguishes an unlisted one from an unverified or
// absent email; the 403 status, not the body, is what separates this from
// deny's 401.
func forbid(err error) error {
	log.Printf("adk: authn: refused an OIDC-authenticated principal: %v", err)
	return fmt.Errorf("%w: %w", ErrForbidden, err)
}

// bearerToken extracts the credential from the Authorization headers. RFC 9110
// makes the scheme case-insensitive.
//
// More than one header is rejected rather than resolved, so a proxy in front
// that forwards the last value cannot disagree with this authenticator about
// which credential arrived.
func bearerToken(authHeaders []string) (string, error) {
	if len(authHeaders) != 1 {
		if len(authHeaders) == 0 {
			return "", errors.New("no Authorization header")
		}
		return "", fmt.Errorf("request carries %d Authorization headers", len(authHeaders))
	}
	scheme, token, found := strings.Cut(authHeaders[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New("authorization header is not a Bearer credential")
	}
	if token = strings.TrimSpace(token); token == "" {
		return "", errors.New("bearer credential is empty")
	}
	return token, nil
}

var _ Authenticator = &googleOIDC{}
