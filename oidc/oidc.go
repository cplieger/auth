// Package oidc wraps coreos/go-oidc to provide OIDC/OAuth2 authentication
// flows with PKCE. It imports the core auth package for types but never
// the reverse.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/cplieger/auth/v2"
	"golang.org/x/oauth2"
)

// Sentinel errors for OIDC operations.
var (
	ErrOIDCDiscovery     = errors.New("oidc: provider discovery failed")
	ErrOIDCExchange      = errors.New("oidc: code exchange failed")
	ErrOIDCTokenInvalid  = errors.New("oidc: ID token verification failed")
	ErrOIDCNonceMismatch = errors.New("oidc: nonce mismatch")
	ErrOIDCConfigInvalid = errors.New("oidc: invalid configuration")
	ErrOIDCNoUsername    = errors.New("oidc: token has no preferred_username or email claim")
)

// Claims holds the verified claims extracted from an OIDC ID token.
type Claims struct {
	Subject           string `json:"sub"`
	Issuer            string `json:"iss"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	EmailVerified     bool   `json:"email_verified"`
}

// Config holds OIDC provider settings. It is an alias of [auth.OIDCConfig]
// (the canonical definition), so a consumer holding the core type passes it to
// [NewProvider] directly with no field-for-field conversion.
type Config = auth.OIDCConfig

// Provider wraps the coreos/go-oidc provider with PKCE support.
type Provider struct {
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   oauth2.Config
	config   Config
}

// GeneratePKCE generates a PKCE code verifier and S256 challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// GenerateState generates a random state string for OIDC flows.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// oidcHTTPTimeout is the maximum time allowed for outbound OIDC HTTP calls.
const oidcHTTPTimeout = 10 * time.Second

// ValidateConfig checks that the required fields of a Config are set.
func ValidateConfig(cfg Config) error {
	if cfg.IssuerURL == "" {
		return fmt.Errorf("%w: issuer_url is required", ErrOIDCConfigInvalid)
	}
	if cfg.ClientID == "" {
		return fmt.Errorf("%w: client_id is required", ErrOIDCConfigInvalid)
	}
	if cfg.RedirectURI == "" {
		return fmt.Errorf("%w: redirect_uri is required", ErrOIDCConfigInvalid)
	}
	return nil
}

// NewProvider creates an OIDC provider from config.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}

	discoverCtx, cancel := context.WithTimeout(ctx, oidcHTTPTimeout)
	defer cancel()

	provider, err := gooidc.NewProvider(discoverCtx, cfg.IssuerURL)
	if err != nil {
		return nil, errors.Join(ErrOIDCDiscovery, err)
	}

	verifier := provider.Verifier(&gooidc.Config{
		ClientID: cfg.ClientID,
	})

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{gooidc.ScopeOpenID, "profile", "email"},
	}

	return &Provider{
		provider: provider,
		verifier: verifier,
		config:   cfg,
		oauth2:   oauth2Cfg,
	}, nil
}

// AuthorizationURL generates the OIDC authorization URL with PKCE and state.
func (p *Provider) AuthorizationURL(state, nonce, codeChallenge string) string {
	return p.oauth2.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange exchanges an authorization code for tokens and validates the ID token.
//
// nonce MUST be the non-empty, single-use, cryptographically random value that was
// bound into the matching AuthorizationURL call and stored server-side for this
// authorization request. Exchange requires the ID token's nonce claim to equal it,
// defending against ID-token replay and injection. Passing nonce == "" is rejected
// with ErrOIDCNonceMismatch (fail closed): a conformant authorization-code flow
// always supplies a non-empty nonce, so an empty value can never satisfy the check.
// PKCE and the state parameter remain in force regardless, but the nonce binding is
// a distinct protection.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (*Claims, *time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, oidcHTTPTimeout)
	defer cancel()

	token, err := p.oauth2.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, nil, errors.Join(ErrOIDCExchange, err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, fmt.Errorf("%w: id_token not present in token response", ErrOIDCTokenInvalid)
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, errors.Join(ErrOIDCTokenInvalid, err)
	}

	if err := checkNonce(nonce, idToken.Nonce); err != nil {
		return nil, nil, err
	}

	// OIDC Core §3.1.3.7 step 3: if multiple audiences, verify azp equals ClientID.
	if len(idToken.Audience) > 1 {
		var rawClaims struct {
			AZP string `json:"azp"`
		}
		if err := idToken.Claims(&rawClaims); err != nil {
			return nil, nil, errors.Join(ErrOIDCTokenInvalid, err)
		}
		if err := checkAuthorizedParty(idToken.Audience, rawClaims.AZP, p.config.ClientID); err != nil {
			return nil, nil, err
		}
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, errors.Join(ErrOIDCTokenInvalid, err)
	}

	var expiry *time.Time
	if !token.Expiry.IsZero() {
		expiry = &token.Expiry
	}

	return &claims, expiry, nil
}

// checkNonce enforces ID-token nonce binding: the ID token's nonce claim MUST
// equal the caller-supplied expected nonce. An empty expected nonce is rejected
// (fail closed) — a conformant authorization-code flow always supplies a
// non-empty nonce, and treating "" as valid would make the equality check
// trivially pass (got == "" == expected), silently disabling replay/injection
// protection. Returns ErrOIDCNonceMismatch on any mismatch or an empty nonce.
func checkNonce(expected, got string) error {
	if expected == "" || got != expected {
		return ErrOIDCNonceMismatch
	}
	return nil
}

// checkAuthorizedParty enforces OIDC Core 3.1.3.7 step 3: an ID token
// carrying more than one audience MUST also carry an azp (authorized party)
// claim equal to the client_id. A single-audience token needs no azp check.
// The returned error wraps ErrOIDCTokenInvalid.
func checkAuthorizedParty(audiences []string, azp, clientID string) error {
	if len(audiences) <= 1 {
		return nil
	}
	if azp != clientID {
		return fmt.Errorf("%w: azp claim %q does not match client_id", ErrOIDCTokenInvalid, azp)
	}
	return nil
}

// usernameFromClaims derives the username for a just-in-time provisioned user:
// preferred_username, falling back to email. It returns ErrOIDCNoUsername when
// the verified token carries neither, so a caller never provisions an account
// with a blank username. The identity is still keyed on (issuer, sub); this
// guards only the human-facing username.
func usernameFromClaims(claims *Claims) (string, error) {
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername, nil
	}
	if claims.Email != "" {
		return claims.Email, nil
	}
	return "", ErrOIDCNoUsername
}

// ResolveUser maps an OIDC identity to a user by (issuer, sub) only. For a new
// identity (existingBySub == nil) it provisions a user from the token claims; it
// returns ErrOIDCNoUsername if the token has neither preferred_username nor email,
// rather than provisioning an account with a blank username.
func ResolveUser(claims *Claims, existingBySub *auth.User) (user *auth.User, isNew bool, err error) {
	if existingBySub != nil {
		return existingBySub, false, nil
	}

	username, err := usernameFromClaims(claims)
	if err != nil {
		return nil, false, err
	}

	return &auth.User{
		Username:    username,
		Email:       claims.Email,
		DisplayName: claims.Name,
		Role:        auth.RoleUser,
		OIDCSub:     claims.Subject,
		OIDCIssuer:  claims.Issuer,
		Enabled:     true,
	}, true, nil
}
