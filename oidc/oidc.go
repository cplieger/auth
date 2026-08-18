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
	"github.com/cplieger/auth/v4"
	"golang.org/x/oauth2"
)

// Sentinel errors for OIDC operations.
var (
	ErrDiscovery     = errors.New("oidc: provider discovery failed")
	ErrExchange      = errors.New("oidc: code exchange failed")
	ErrTokenInvalid  = errors.New("oidc: ID token verification failed")
	ErrNonceMismatch = errors.New("oidc: nonce mismatch")
	ErrConfigInvalid = errors.New("oidc: invalid configuration")
	ErrNoUsername    = errors.New("oidc: token has no preferred_username or email claim")
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

// The opaque random values of the authorization-code flow each get a distinct
// type: they are indistinguishable strings, no guard can validate one against
// another, and [Provider.AuthorizationURL] and [Provider.Exchange] take
// several adjacent — so a silent transposition would still run and quietly
// disable the protection (state, nonce, PKCE) that value carries. State,
// Nonce, and CodeVerifier also cross the consumer's persistence boundary
// ([auth.OIDCStateStore]), so their canonical definitions live in the root
// auth package (the import direction is oidc → auth) and the names here are
// aliases; CodeChallenge and Code never cross the store SPI and stay local.

// State is the CSRF-binding state parameter of an authorization request. It
// is an alias of [auth.OIDCState] (the canonical definition), so the value
// flows from [GenerateState] through a consumer's [auth.OIDCStateStore] and
// back without conversion.
type State = auth.OIDCState

// Nonce is the ID-token replay-protection nonce bound into an authorization
// request and verified against the token's nonce claim at [Provider.Exchange].
// It is an alias of [auth.OIDCNonce] (the canonical definition).
type Nonce = auth.OIDCNonce

// CodeChallenge is the PKCE S256 challenge sent in the authorization request.
type CodeChallenge string

// Code is the single-use authorization code returned to the redirect URI.
type Code string

// CodeVerifier is the PKCE verifier matching a previously sent
// [CodeChallenge]. It is an alias of [auth.OIDCCodeVerifier] (the canonical
// definition).
type CodeVerifier = auth.OIDCCodeVerifier

// Provider wraps the coreos/go-oidc provider with PKCE support. Create with
// [NewProvider]; the zero value has no discovered endpoints or token verifier
// (Exchange panics on the nil verifier).
type Provider struct {
	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	oauth2   oauth2.Config
	config   Config
}

// GeneratePKCE generates a PKCE code verifier and S256 challenge. The two
// results are distinct types (they are born adjacent and equally opaque), so
// the whole chain from generation through storage to [Provider.Exchange] is
// compiler-checked with no hand-written conversion for a caller to transpose.
func GeneratePKCE() (CodeVerifier, CodeChallenge, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	return CodeVerifier(verifier), CodeChallenge(challenge), nil
}

// GenerateState generates a random state value for OIDC flows, typed at the
// producer so it cannot be transposed with the other opaque randoms on its way
// to [Provider.AuthorizationURL] or a consumer's [auth.OIDCStateStore].
func GenerateState() (State, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return State(hex.EncodeToString(b)), nil
}

// oidcHTTPTimeout is the maximum time allowed for outbound OIDC HTTP calls.
const oidcHTTPTimeout = 10 * time.Second

// ValidateConfig checks that the required fields of a Config are set.
func ValidateConfig(cfg Config) error {
	if cfg.IssuerURL == "" {
		return fmt.Errorf("%w: issuer_url is required", ErrConfigInvalid)
	}
	if cfg.ClientID == "" {
		return fmt.Errorf("%w: client_id is required", ErrConfigInvalid)
	}
	if cfg.RedirectURI == "" {
		return fmt.Errorf("%w: redirect_uri is required", ErrConfigInvalid)
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
		return nil, errors.Join(ErrDiscovery, err)
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
//
// state and codeChallenge MUST be the non-empty, single-use, cryptographically
// random values minted for this authorization request ([GenerateState],
// [GeneratePKCE]). An empty state is rejected with a descriptive error (fail
// closed): a conformant authorization-code flow always supplies a non-empty
// state, and emitting a request without one would silently drop the CSRF
// binding of the callback. An empty codeChallenge is rejected the same way:
// the request would silently carry no PKCE protection. This mirrors
// [Provider.Exchange]'s empty-nonce posture.
func (p *Provider) AuthorizationURL(state State, nonce Nonce, codeChallenge CodeChallenge) (string, error) {
	if state == "" {
		return "", errors.New("oidc: empty state: the authorization request would carry no CSRF binding")
	}
	if codeChallenge == "" {
		return "", errors.New("oidc: empty code challenge: the authorization request would carry no PKCE protection")
	}
	return p.oauth2.AuthCodeURL(string(state),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("code_challenge", string(codeChallenge)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

// Exchange exchanges an authorization code for tokens and validates the ID token.
//
// nonce MUST be the non-empty, single-use, cryptographically random value that was
// bound into the matching AuthorizationURL call and stored server-side for this
// authorization request. Exchange requires the ID token's nonce claim to equal it,
// defending against ID-token replay and injection. Passing nonce == "" is rejected
// with ErrNonceMismatch (fail closed): a conformant authorization-code flow
// always supplies a non-empty nonce, so an empty value can never satisfy the check.
// PKCE and the state parameter remain in force regardless, but the nonce binding is
// a distinct protection.
func (p *Provider) Exchange(ctx context.Context, code Code, codeVerifier CodeVerifier, nonce Nonce) (*Claims, *time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, oidcHTTPTimeout)
	defer cancel()

	token, err := p.oauth2.Exchange(ctx, string(code),
		oauth2.SetAuthURLParam("code_verifier", string(codeVerifier)),
	)
	if err != nil {
		return nil, nil, errors.Join(ErrExchange, err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, fmt.Errorf("%w: id_token not present in token response", ErrTokenInvalid)
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, errors.Join(ErrTokenInvalid, err)
	}

	if err := checkNonce(string(nonce), idToken.Nonce); err != nil {
		return nil, nil, err
	}

	// OIDC Core §3.1.3.7 step 3: if multiple audiences, verify azp equals ClientID.
	if len(idToken.Audience) > 1 {
		var rawClaims struct {
			AZP string `json:"azp"`
		}
		if err := idToken.Claims(&rawClaims); err != nil {
			return nil, nil, errors.Join(ErrTokenInvalid, err)
		}
		if err := checkAuthorizedParty(idToken.Audience, rawClaims.AZP, p.config.ClientID); err != nil {
			return nil, nil, err
		}
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, errors.Join(ErrTokenInvalid, err)
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
// protection. Returns ErrNonceMismatch on any mismatch or an empty nonce.
func checkNonce(expected, got string) error {
	if expected == "" || got != expected {
		return ErrNonceMismatch
	}
	return nil
}

// checkAuthorizedParty enforces OIDC Core 3.1.3.7 step 3: an ID token
// carrying more than one audience MUST also carry an azp (authorized party)
// claim equal to the client_id. A single-audience token needs no azp check.
// The returned error wraps ErrTokenInvalid.
func checkAuthorizedParty(audiences []string, azp, clientID string) error {
	if len(audiences) <= 1 {
		return nil
	}
	if azp != clientID {
		return fmt.Errorf("%w: azp claim %q does not match client_id", ErrTokenInvalid, azp)
	}
	return nil
}

// usernameFromClaims derives the username for a just-in-time provisioned user:
// preferred_username, falling back to email. It returns ErrNoUsername when
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
	return "", ErrNoUsername
}

// ResolveUser maps an OIDC identity to a user by (issuer, sub) only. For a new
// identity (existingBySub == nil) it provisions a user from the token claims; it
// returns ErrNoUsername if the token has neither preferred_username nor email,
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
