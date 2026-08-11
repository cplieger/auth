# auth

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/auth.svg)](https://pkg.go.dev/github.com/cplieger/auth)
[![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/auth)](https://github.com/cplieger/auth/blob/main/go.mod)
[![Test coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/auth/badges/coverage.json)](https://github.com/cplieger/auth/actions/workflows/coverage.yml)
[![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/auth/badges/mutation.json)](https://github.com/cplieger/auth/issues?q=label%3Agremlins-tracker)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13199/badge)](https://www.bestpractices.dev/projects/13199)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cplieger/auth/badge)](https://scorecard.dev/viewer/?uri=github.com/cplieger/auth)

> Go authentication library: Argon2id passwords, WebAuthn/passkeys, OIDC, sessions, API keys, and RBAC.

A standalone Go authentication library providing password hashing (Argon2id with OWASP parameters), WebAuthn/FIDO2 passkey ceremonies, OIDC provider integration with PKCE, session management with idle/absolute timeouts, API key generation and verification, CSRF token helpers, password-reset/email-verification token primitives, and role-based access control helpers.

Dependencies: `golang.org/x/crypto`, `github.com/go-webauthn/webauthn`, `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`.

**Note:** HTTP handlers are app-specific and intentionally not included. Build your own HTTP layer on the exported primitives.

## Install

```sh
go get github.com/cplieger/auth/v2@latest
```

## Usage

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/cplieger/auth/v2"
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

	// Set up authenticator with your store implementation (functional options).
	// NewAuthenticator returns an error if the configuration is unusable (e.g. a
	// __Host- cookie posture combined with a Domain or a non-root Path).
	authenticator, err := auth.NewAuthenticator(
		myStore, // implements auth.SessionStore
		auth.WithIdleTimeout(1*time.Hour),
		auth.WithAbsTimeout(24*time.Hour),
		auth.WithLoginPath("/login"),
		auth.WithCookie(auth.DefaultCookieConfig()),
	)
	if err != nil {
		log.Fatalf("auth: %v", err)
	}

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

All configuration is via functional options and function parameters. The library has no import-time side effects, no environment reads, and no global state.

- `WithLogger(l)`: optional `*slog.Logger`; if nil, uses `slog.Default()`
- `WithLoginPath(path)`: redirect path for unauthenticated browser requests (default: `"/login"`)
- `WithCookie(cfg)`: configurable cookie Name, Posture, Path, SameSite, Domain, TrustForwardedHeaders (see `CookieConfig`)
- `WithIdleTimeout(d)`: session idle timeout (default: 1h)
- `WithAbsTimeout(d)`: session absolute timeout (default: 24h)
- `WithBypass(fn)`: development bypass hook (synthetic admin user); a production-safety warning fires once, on the first request the hook actually grants
- `WithVerifiers(vs []CredentialVerifier)`: replace the default verifier chain (`SessionVerifier` + `APIKeyVerifier`) with your own
- `WithActivityThrottle(d time.Duration)`: call `UpdateSessionActivity` at most once per `d` per session instead of on every request (default `0`: write on every request). `d` must be less than the idle timeout or construction returns an error, since the persisted last-activity lags by up to `d`.
- `WithUnauthorizedResponse(fn)`: replace `RequireAuth`'s default unauthorized response (302 to the login path for browsers, 401 JSON otherwise) with your own writer. The hook owns both branches; call `IsBrowserRequest` inside it to keep a redirect path.
- `WithTimeoutSource(fn)`: resolve the idle/absolute session timeouts per verification from a callback (for hot-reloadable config). Non-positive callback values fall back to the static options; the activity throttle is clamped to half the resolved idle timeout so a shrunken idle cannot expire active sessions.
- `NewHasher(params, ...HasherOption)`: configurable Argon2id parameters; use `WithPepper([]byte)` for HMAC peppering
- `GenerateAPIKey(prefix)`: pass your key prefix (e.g. `"ak_"`)
- `ValidatePasswordContext(password, username, forbiddenWords)`: pass app-specific forbidden words

### Cookie Configuration

```go
cfg := auth.CookieConfig{
    Name:     "my_session",          // base name (default: "auth_session")
    Posture:  auth.PostureSecure,    // __Host- + Secure (default); see CookiePosture table below
    Path:     "/",                   // cookie path (default: "/")
    Domain:   "",                    // cookie domain (default: unset; must stay unset under a __Host- posture)
    SameSite: http.SameSiteLaxMode,  // (default: Lax)
    // TrustForwardedHeaders: true,  // only behind a proxy that always sets X-Forwarded-Proto
}
authenticator, err := auth.NewAuthenticator(myStore, auth.WithCookie(cfg))
if err != nil {
    log.Fatalf("auth: %v", err) // cfg rejected: see CookieConfig.Validate
}
```

#### CookiePosture

`CookiePosture` controls the cookie name prefix and Secure flag strategy:

| Value               | Behavior                                                                                                                                                                                                                             |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| (default)           | Static `__Host-` prefix when `Secure` is true/auto-HTTPS                                                                                                                                                                             |
| `PosturePerRequest` | Selects the cookie name and Secure flag at request time: HTTPS requests get `__Host-`+base+`Secure`; plain HTTP gets the bare base name without the Secure flag. Respects `TrustForwardedHeaders` for `X-Forwarded-Proto` detection. |

`PosturePerRequest` suits services that accept both HTTP and HTTPS traffic, such as a load balancer that terminates TLS for some paths but not others.

## API

Grouped summary of the exported surface. Signatures and full semantics live in the [Go Reference](https://pkg.go.dev/github.com/cplieger/auth/v2).

- **Password hashing:** `HashPassword` / `VerifyPassword` / `NeedsRehash` (Argon2id PHC strings, OWASP defaults), `DummyHash` (constant-time timing equalization for unknown-user logins), `DefaultArgon2Params`, `NewHasher` + `WithPepper` (custom parameters, HMAC pepper), `Hasher.Hash` / `Hasher.Verify` / `Hasher.NeedsRehash`, `ValidatePasswordLength` (NIST, max 128), `ValidatePasswordContext`, `CheckBreachedPassword` (HIBP k-anonymity).
- **Sessions and tokens:** `GenerateSessionToken` (256-bit), `RotateSessionToken`, `ValidateSession`, `SessionHash`, `HexSHA256`, `CSRFToken` / `VerifyCSRFToken` (bound to the session hash), `GenerateOpaqueToken` / `VerifyOpaqueToken` (password reset, email verification).
- **Cookies:** `CookieConfig.CookieName` / `SetCookie` / `ReadCookie` / `ClearCookie`, plus the default-config free functions `SessionCookieName` / `SetSessionCookie` / `ReadSessionCookie` / `ClearSessionCookie`.
- **API keys:** `GenerateAPIKey`, `VerifyAPIKey` (constant-time hash equality plus expiry check), `APIKeyHash`.
- **Middleware and guards:** `NewAuthenticator` and `NewSessionVerifier` (both return an error on an unusable config; see `CookieConfig.Validate`), `NewAPIKeyVerifier` (reads the `X-Api-Key` header only, never a URL query parameter, per CWE-598), `Authenticator.Authenticate` / `Authenticator.RequireAuth`, `HasRole` (flat RBAC), `ValidateRedirectURI` (relative paths only), `CanDisableAuthMethod`, `IsBrowserRequest`. The `WithVerifiers` / `WithActivityThrottle` / `WithUnauthorizedResponse` / `WithTimeoutSource` options are described under [Configuration](#configuration).
- **Interfaces:** `CredentialVerifier` (pluggable credential verification), `SessionStore` and `webauthn.Store` (consumer-implemented storage), `store.Composite` (composite store interface, subpackage `auth/store`).
- **WebAuthn (`github.com/cplieger/auth/v2/webauthn`):** `NewWebAuthn`, `NewWebAuthnUser`, `BeginRegistration` / `FinishRegistration` / `BeginLogin` / `FinishLogin`, `BeginConditionalLogin` (conditional mediation, autofill UI), `CompleteLogin` (store-backed login completion; the caller keeps account-status policy and session creation).
- **OIDC (`github.com/cplieger/auth/v2/oidc`):** `NewProvider` and `ValidateConfig` (both take an `oidc.Config`), `GenerateState`, `GeneratePKCE` (S256), `Provider.AuthorizationURL`, `Provider.Exchange` (verifies the ID token; an empty or mismatched nonce fails closed with `ErrOIDCNonceMismatch`), `ResolveUser` (maps an OIDC identity by issuer and subject to a user; `ErrOIDCNoUsername` when the token carries neither `preferred_username` nor `email`).

## Subpackages

### `auth/store`

Composite interface `store.Composite`.

### `auth/ratelimit`

Dual sliding-window per-IP + per-account authentication brute-force rate limiter (OWASP ASVS 2.2.1). Standard library only (`context`, `log/slog`, `sync`, `time`).

```go
rl := ratelimit.NewRateLimiter(ctx, ratelimit.DefaultConfig())
defer rl.Stop()
if allowed, retryAfter := rl.Allow(clientIP, username); !allowed {
    // reject; retry after retryAfter
}
// On each FAILED login attempt, record it so it counts toward the limit:
rl.Record(clientIP, username)
// On successful login, clear the failure counters:
rl.Reset(clientIP, username)
```

### `auth/authtest`

Exported in-memory `SessionStore` implementation for consumer tests.

```go
store := authtest.NewMemStore()
store.AddUser(&auth.User{Username: "test", Role: auth.RoleUser, Enabled: true})
```

## Unsupported by Design

The following features are intentionally out of scope.

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

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
conventions and how to run the checks locally.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE).
