# auth

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/auth.svg)](https://pkg.go.dev/github.com/cplieger/auth)
[![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/auth)](https://github.com/cplieger/auth/blob/main/go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/cplieger/auth)](https://goreportcard.com/report/github.com/cplieger/auth)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/auth/badges/coverage.json)](https://github.com/cplieger/auth/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/auth/badges/mutation.json)](https://github.com/cplieger/auth/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13199/badge)](https://www.bestpractices.dev/projects/13199)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/auth/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/auth)

> Go authentication library: Argon2id passwords, WebAuthn/passkeys, OIDC, sessions, API keys, and RBAC.

A standalone Go authentication library providing password hashing (Argon2id with OWASP parameters), WebAuthn/FIDO2 passkey ceremonies, OIDC provider integration with PKCE, session management with idle/absolute timeouts, API key generation and verification, CSRF token helpers, password-reset/email-verification token primitives, and role-based access control helpers.

Dependencies: `golang.org/x/crypto`, `github.com/go-webauthn/webauthn`, `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`.

**Note:** HTTP handlers are app-specific and intentionally not included. Consumers should implement their own HTTP layer using the exported authentication primitives.

## Install

```sh
go get github.com/cplieger/auth@latest
```

## Usage

```go
package main

import (
	"net/http"
	"time"

	"github.com/cplieger/auth"
)

func main() {
	// Hash a password (package-level with OWASP defaults)
	hash, _ := auth.HashPassword("my-secure-password")

	// Verify
	ok, _ := auth.VerifyPassword("my-secure-password", hash)
	_ = ok

	// Or use a configurable Hasher with custom params and optional pepper
	hasher, _ := auth.NewHasher(auth.Argon2Params{
		Memory: 65536, Iterations: 3, Parallelism: 2,
		SaltLength: 16, KeyLength: 32,
	}, auth.WithPepper([]byte("my-secret-pepper")))
	hash2, _ := hasher.Hash("my-secure-password")
	ok2, _ := hasher.Verify("my-secure-password", hash2)
	_, _ = hash2, ok2

	// Set up authenticator with your store implementation (functional options)
	authenticator := auth.NewAuthenticator(
		myStore, // implements auth.SessionStore
		auth.WithIdleTimeout(1*time.Hour),
		auth.WithAbsTimeout(24*time.Hour),
		auth.WithLoginPath("/login"),
		auth.WithCookie(auth.DefaultCookieConfig()),
	)

	// Use in HTTP handler
	http.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
		user, _, ok := authenticator.RequireAuth(w, r)
		if !ok {
			return
		}
		_ = user
	})
}
```

## Configuration

All configuration is via functional options and function parameters — no import-time side effects, no environment variable reads, no global state initialization.

- `WithLogger(l)`: optional `*slog.Logger`; if nil, uses `slog.Default()`
- `WithLoginPath(path)`: redirect path for unauthenticated browser requests (default: `"/login"`)
- `WithCookie(cfg)`: configurable cookie name/prefix, Path, SameSite, Domain, Secure (see `CookieConfig`)
- `WithIdleTimeout(d)`: session idle timeout (default: 1h)
- `WithAbsTimeout(d)`: session absolute timeout (default: 24h)
- `WithBypass(fn)`: bypass function for development (synthetic admin user)
- `WithVerifiers(vs []CredentialVerifier)`: override the default verifier chain. When set, `Authenticate` iterates the supplied chain instead of the hardcoded default (`SessionVerifier` + `APIKeyVerifier`).
- `WithActivityThrottle(d time.Duration)`: when `d>0`, `SessionVerifier` maintains a per-hash last-write map and calls `UpdateSessionActivity` at most once per `d` per hash. `d==0` (default) preserves the current write-on-every-request behavior.
- `NewHasher(params, ...HasherOption)`: configurable Argon2id parameters; use `WithPepper([]byte)` for HMAC peppering
- `GenerateAPIKey(prefix)`: pass your key prefix (e.g. `"ak_"`)
- `ValidatePasswordContext(password, username, forbiddenWords)`: pass app-specific forbidden words

### Cookie Configuration

```go
cfg := auth.CookieConfig{
    Name:     "my_session",       // base name (default: "auth_session")
    Prefix:   "__Host-",          // HTTPS prefix (default: "__Host-"; "" to disable)
    Path:     "/",                // cookie path (default: "/")
    Domain:   "",                 // cookie domain (default: unset)
    SameSite: http.SameSiteLaxMode, // (default: Lax)
    Secure:   nil,                // nil=auto (true when HTTPS), or explicit *bool
}
authenticator := auth.NewAuthenticator(myStore, auth.WithCookie(cfg))
```

#### CookiePosture

`CookiePosture` controls the cookie name prefix and Secure flag strategy:

| Value               | Behavior                                                                                                                                                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| (default)           | Static `__Host-` prefix when `Secure` is true/auto-HTTPS                                                                                                                                                                                          |
| `PosturePerRequest` | Selects cookie name and Secure flag at request time via `isHTTPS(r)`. HTTPS requests get `__Host-`+base+`Secure`; plain HTTP gets the bare base name without the Secure flag. Respects `TrustForwardedHeaders` for `X-Forwarded-Proto` detection. |

`PosturePerRequest` is useful for services that accept both HTTP and HTTPS traffic (e.g., behind a load balancer that terminates TLS for some paths but not others).

## API

### Password Hashing

- `HashPassword(password) (string, error)` — Argon2id hash in PHC string format (OWASP defaults)
- `VerifyPassword(password, hash) (bool, error)` — verify hash
- `NeedsRehash(encodedHash) bool` — check if hash uses outdated parameters
- `DummyHash() string` — pre-computed hash for constant-time login timing equalization
- `DefaultArgon2Params() Argon2Params` — OWASP-recommended Argon2id parameters
- `NewHasher(params, ...HasherOption) (*Hasher, error)` — configurable Argon2id hasher
- `WithPepper(pepper) HasherOption` — enable HMAC peppering on a Hasher
- `Hasher.Hash(password) (string, error)` — hash with custom params
- `Hasher.Verify(password, hash) (bool, error)` — verify with custom params
- `Hasher.NeedsRehash(hash) bool` — check against custom params
- `ValidatePasswordLength(password, passwordOnly) error` — NIST length check (max 128)
- `ValidatePasswordContext(password, username, forbiddenWords) error` — contextual check
- `CheckBreachedPassword(ctx, client, password) (bool, error)` — HIBP k-anonymity

### Sessions & Tokens

- `GenerateSessionToken() (plaintext, hash, error)` — 256-bit session token
- `RotateSessionToken(oldPlaintext) (newPlaintext, newHash, oldHash, error)` — rotation helper
- `ValidateSession(sess, idle, abs, now) error` — session expiry check
- `SessionHash(token) string` — SHA-256 hash of plaintext token
- `HexSHA256(s) string` — hex-encoded SHA-256
- `CSRFToken(key, sessionHash) (string, error)` — generate CSRF token bound to session
- `VerifyCSRFToken(key, sessionHash, token, maxAge) error` — verify CSRF token
- `GenerateOpaqueToken() (plaintext, hash, error)` — for password-reset/email-verification
- `VerifyOpaqueToken(plaintext, storedHash, expiresAt) error` — verify opaque token

### Cookie Management

- `CookieConfig.CookieName(r) string` — resolve cookie name for request
- `CookieConfig.SetCookie(w, r, token, maxAge)` — set session cookie
- `CookieConfig.ReadCookie(r) string` — read session token
- `CookieConfig.ClearCookie(w, r)` — clear session cookie
- `SessionCookieName(r) / SetSessionCookie / ReadSessionCookie / ClearSessionCookie` — default-config free functions

### API Keys

- `GenerateAPIKey(keyPrefix) (plaintext, hash, displayPrefix, displaySuffix, error)` — API key generation
- `VerifyAPIKey(ctx, store, key) (*Key, error)` — API key verification (constant-time hash equality + expiry check)
- `APIKeyHash(key) string` — SHA-256 hash of API key

### WebAuthn

- `NewWebAuthn(rpID, rpDisplayName, rpOrigins) (*webauthn.WebAuthn, error)` — WebAuthn setup
- `NewWebAuthnUser(user, creds) (*WebAuthnUser, error)` — adapt User to webauthn.User interface
- `BeginRegistration / FinishRegistration / BeginLogin / FinishLogin` — WebAuthn ceremonies
- `BeginConditionalLogin(wa) (*CredentialAssertion, *SessionData, error)` — conditional mediation (autofill UI)

### OIDC

- `NewOIDCProvider(ctx, cfg) (*OIDCProvider, error)` — OIDC provider with PKCE
- `ValidateOIDCConfig(cfg) error` — validate OIDC configuration
- `GenerateOIDCState() (string, error)` — random state parameter
- `GeneratePKCE() (verifier, challenge, error)` — PKCE S256

### Auth Middleware

- `NewAuthenticator(store, ...Option) *Authenticator` — create authenticator with functional options
- `NewSessionVerifier(store, ...Option) *SessionVerifier` — session-cookie credential verifier
- `NewAPIKeyVerifier(store, ...Option) *APIKeyVerifier` — API-key credential verifier
- `Authenticator.Authenticate(r) (*User, string, error)` — resolve request to user
- `Authenticator.RequireAuth(w, r) (*User, string, bool)` — auth guard
- `HasRole(user, role) bool` — RBAC check
- `ValidateRedirectURI(uri) string` — safe relative-path redirect validation
- `CanDisableAuthMethod(method, hasPassword, passkeyCount, oidcEnabled, oidcLinked) bool` — check method removal safety
- `IsBrowserRequest(r) bool` — detect browser vs API client
- `WithVerifiers(vs []CredentialVerifier)` — override the default verifier chain
- `WithActivityThrottle(d time.Duration)` — throttle `UpdateSessionActivity` writes (see Configuration)
- `CredentialVerifier` — interface for pluggable credential verifiers
- `SessionStore` / `WebAuthnStore` — interfaces for consumer to implement
- `store.Composite` — composite interface (subpackage `github.com/cplieger/auth/store`)

## Subpackages

### `auth/store`

Composite interface `store.Composite` (renamed from `store.AuthStore` to disambiguate from `auth.AuthStore` in middleware.go). Consumers referencing `store.AuthStore` should update their alias target to `store.Composite`.

### `auth/ratelimit`

Dual sliding-window per-IP + per-account authentication brute-force rate limiter (OWASP ASVS 2.2.1). Standard library only (`context`, `sync`, `time`).

```go
rl := ratelimit.NewRateLimiter(ctx, ratelimit.DefaultConfig())
defer rl.Stop()
if allowed, retryAfter := rl.Allow(clientIP, username); !allowed {
    // reject; retry after retryAfter
}
// On successful login, clear the failure counters:
rl.Reset(clientIP, username)
```

### `auth/authtest`

Exported in-memory `SessionStore` implementation for consumer tests.

```go
store := authtest.NewMemStore()
store.AddUser(&auth.User{Username: "test", Role: auth.RoleUser, Enabled: true})
```

## Unsupported Features (by design)

The following features are intentionally out of scope. Each has a documented rationale and, where applicable, a recommended alternative.

| Feature                                | Rationale                                                                                                                |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Full OIDC token-refresh orchestration  | Library handles authentication, not long-lived API access. Consumer uses `oauth2.TokenSource`.                           |
| Multi-provider OIDC registry           | Consumer instantiates multiple `OIDCProvider` instances.                                                                 |
| WebAuthn MDS verification              | Enterprise feature with large surface. Consumer can call `credential.Verify(mdsProvider)` using stored `RawAttestation`. |
| OIDC back-channel logout               | Enterprise SSO feature beyond scope of auth-primitive library.                                                           |
| Hierarchical RBAC / permission sets    | Library provides `HasRole` for flat role check. Use casbin/ory-keto for complex RBAC.                                    |
| Cookie encryption/signing              | Opaque-token architecture; cookie value is a random token, not sensitive data.                                           |
| OIDC userinfo endpoint                 | ID token claims sufficient for authentication. Consumer can call `provider.UserInfo()`.                                  |
| WebAuthn attestation conveyance        | Default `none` is correct for most RPs per FIDO Alliance guidance.                                                       |
| WebAuthn credential filtering (AAGUID) | Enterprise policy. Consumer can use go-webauthn's filtering directly.                                                    |
| Passkey well-known endpoints           | Browser/credential-manager concern, not server-auth-library concern.                                                     |
| CSRF middleware (full HTTP layer)      | Library provides `CSRFToken`/`VerifyCSRFToken` primitives; full middleware is HTTP-framework-specific.                   |

## License

GPL-3.0 — see [LICENSE](LICENSE).
