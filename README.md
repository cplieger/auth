# auth
> Go authentication library: Argon2id passwords, WebAuthn/passkeys, OIDC, sessions, API keys, and RBAC.

A standalone, decoupled authentication package extracted from Subflux. Provides password hashing (Argon2id with OWASP parameters), WebAuthn/FIDO2 passkey ceremonies, OIDC provider integration with PKCE, session management with idle/absolute timeouts, API key generation and verification, and role-based access control helpers. Dependencies: `golang.org/x/crypto`, `github.com/go-webauthn/webauthn`, `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`.

**Note:** HTTP handlers are app-specific and intentionally not included. Consumers should implement their own HTTP layer using the exported authentication primitives.

## Install
<!-- TODO: registry/pull link -->
Go: `go get github.com/cplieger/auth@latest`

## Usage
```go
package main

import (
	"net/http"
	"time"

	"github.com/cplieger/auth"
)

func main() {
	// Hash a password
	hash, _ := auth.HashPassword("my-secure-password")

	// Verify
	ok, _ := auth.VerifyPassword("my-secure-password", hash)
	_ = ok

	// Set up authenticator with your store implementation
	authenticator := &auth.Authenticator{
		Store:       myStore, // implements auth.SessionStore
		IdleTimeout: 1 * time.Hour,
		AbsTimeout:  24 * time.Hour,
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

## API
- `HashPassword(password) (string, error)` — Argon2id hash
- `VerifyPassword(password, hash) (bool, error)` — verify hash
- `ValidatePasswordLength(password, passwordOnly) error` — NIST length check
- `CheckBreachedPassword(ctx, client, password) (bool, error)` — HIBP k-anonymity
- `GenerateSessionToken() (plaintext, hash, error)` — 256-bit session token
- `ValidateSession(sess, idle, abs, now) error` — session expiry check
- `GenerateAPIKey() (plaintext, hash, prefix, suffix, error)` — API key generation
- `VerifyAPIKey(ctx, store, key) (*Key, error)` — API key verification
- `NewWebAuthn(rpID, name, origins) (*webauthn.WebAuthn, error)` — WebAuthn setup
- `BeginRegistration / FinishRegistration / BeginLogin / FinishLogin` — WebAuthn ceremonies
- `NewOIDCProvider(ctx, cfg) (*OIDCProvider, error)` — OIDC provider with PKCE
- `GeneratePKCE() (verifier, challenge, error)` — PKCE S256
- `Authenticator.Authenticate(r) (*User, string, error)` — resolve request to user
- `Authenticator.RequireAuth(w, r) (*User, string, bool)` — auth guard
- `HasRole(user, role) bool` — RBAC check
- `SessionStore` / `WebAuthnStore` — interfaces for consumer to implement
- `store.AuthStore` — composite interface (subpackage `github.com/cplieger/auth/store`)

## License
GPL-3.0 — see [LICENSE](LICENSE).
