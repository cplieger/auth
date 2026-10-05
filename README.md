# auth

[![Go Reference](https://pkg.go.dev/badge/github.com/cplieger/auth/v6.svg)](https://pkg.go.dev/github.com/cplieger/auth/v6) [![Go version](https://img.shields.io/github/go-mod/go-version/cplieger/auth)](https://github.com/cplieger/auth/blob/main/go.mod) [![Mutation](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cplieger/auth/badges/mutation.json)](https://github.com/cplieger/auth/issues?q=label%3Agremlins-tracker)

auth gives your Go web service its login building blocks: Argon2id passwords, passkeys, OIDC sign-in, sessions, API keys and CSRF tokens. You write the HTTP handlers and the storage.

It replaces the hashing, token, cookie and passkey code you would otherwise assemble around `net/http`. It reads no environment variables, and every setting lives on the value you construct. It needs Go 1.27 or later and is licensed under Apache-2.0. It has five direct dependencies at run time: `golang.org/x/crypto`, `golang.org/x/oauth2`, `golang.org/x/text`, `go-webauthn/webauthn` and `coreos/go-oidc`.

## Why use it

auth is built for a Go service that owns its login pages and database.

- Passwords hash with Argon2id at OWASP's parameters, with an optional HMAC pepper and a `DummyHash` that evens out login timing.
- Your store keeps only the SHA-256 hash of each 256-bit random session token. The cookie holds only the token, so it needs no encryption or signing.
- Passkey ceremonies check each browser origin against the relying-party ID, and the API exposes no go-webauthn type.
- OIDC sign-in sends a PKCE S256 challenge and checks the ID token's nonce.
- Secrets are compared in constant time.
- You implement only the storage interfaces for the features you use, and `authtest` is an in-memory test store.

Consider [Authboss](https://github.com/aarondl/authboss) if you want ready-made registration, recovery and two-factor flows with HTML or JSON views. Consider [Ory Kratos](https://github.com/ory/kratos) if you want identity as a separate server with login, recovery and multi-factor flows over HTTP APIs.

## Install

```sh
go get github.com/cplieger/auth/v6@latest
```

## Usage

An `Authenticator` guards a route. Its store is your implementation of `auth.AuthenticatorStore`, and this example uses the in-memory test store instead.

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/cplieger/auth/v6"
	"github.com/cplieger/auth/v6/authtest"
)

func main() {
	store := authtest.NewMemStore() // use your database-backed store here

	authn, err := auth.New(store,
		auth.WithIdleTimeout(time.Hour),
		auth.WithAbsTimeout(24*time.Hour),
		auth.WithCookie(auth.DefaultCookieConfig()),
	)
	if err != nil {
		log.Fatal(err) // the cookie or timeout settings cannot work
	}

	http.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		user, _, ok := authn.RequireAuth(w, r) // the second value is the session hash
		if !ok {
			return // RequireAuth has already answered
		}
		fmt.Fprintln(w, user.Username)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

`RequireAuth` redirects a browser to `/login`, or to the path you set with `WithLoginPath`, and answers any other client with a 401 JSON body. It reads the session cookie first, then the `X-Api-Key` header.

Signing in is your handler. This one checks a password and starts a session. Here `store` implements `auth.UserStore` and `auth.SessionPersister`, and `cookie` is the `CookieConfig` you pass to `WithCookie`.

```go
func signIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, err := auth.NormalizeUsername(r.FormValue("username"))
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
		return
	}
	user, found, err := store.UserByUsername(ctx, name)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	hash := auth.DummyHash() // the same work for an unknown username
	if found {
		hash = user.PasswordHash
	}
	ok, err := auth.VerifyPassword(r.FormValue("password"), hash)
	if err != nil || !ok || !found || !user.Enabled {
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
		return
	}
	token, tokenHash := auth.GenerateSessionToken()
	now := time.Now()
	err = store.CreateSession(ctx, &auth.Session{
		TokenHash: tokenHash, UserID: user.ID, AuthMethod: auth.MethodPassword,
		CreatedAt: now, LastActivity: now,
	})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	cookie.SetCookie(w, r, token, 0)
	http.Redirect(w, r, auth.ValidateRedirectURI(r.FormValue("next")), http.StatusSeeOther)
}
```

The `ratelimit` package limits failed logins per IP address and per account. Check it before the password, record each failure, and reset it on success:

```go
rl := ratelimit.New(ctx, ratelimit.DefaultConfig())
defer func() {
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rl.Shutdown(sctx); err != nil {
		log.Printf("ratelimit shutdown: %v", err)
	}
}()

ip, user := ratelimit.ClientIP(clientIP), ratelimit.Username(username)
if allowed, retryAfter := rl.Allow(ip, user); !allowed {
	return fmt.Errorf("too many attempts, retry in %s", retryAfter)
}
if !passwordOK {
	rl.Record(ip, user) // count the failed attempt
	return errSignInFailed
}
rl.Reset(ip, user) // clear the count after a successful sign-in
```

The package examples on pkg.go.dev show more cases, and `go test` keeps them true.

## API

- `HashPassword`, `VerifyPassword`, `NeedsRehash`, `DummyHash` and `NewHasher` hash passwords. `ValidateSoloPasswordLength`, `ValidateMultiFactorPasswordLength`, `ValidatePasswordContext` and `CheckBreachedPassword` check them.
- `NormalizeUsername` maps a username to one canonical form, so `Müller` and `MÜLLER` sign in to the same account.
- `GenerateSessionToken`, `RotateSessionToken`, `CSRFToken` and `GenerateOpaqueToken` make tokens, the last one for password-reset and email-verification links. `VerifyCSRFToken` and `VerifyOpaqueToken` check them, and `ValidateSession` checks a session's timeouts.
- `CookieConfig` sets, reads and clears the session cookie. `GenerateAPIKey` and `VerifyAPIKey` handle API keys.
- `New` builds the `Authenticator`. `HasRole`, `ValidateRedirectURI`, `CanDisableMethod` and `IsBrowserRequest` are the checks around it.
- `UserStore`, `SessionPersister`, `PasskeyStore`, `KeyStore` and `OIDCStateStore` are the storage interfaces you implement.
- The `webauthn` package runs passkey ceremonies, `oidc` runs OIDC sign-in, `ratelimit` limits failed logins, and `authtest` is an in-memory store for tests.

The full reference is on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/auth/v6).

## Security

auth hardens the building blocks, and the security of your service depends on how you wire them.

- Each password hash has its own random salt. Password hashes, API keys, CSRF tokens and opaque tokens are compared in constant time.
- The default cookie carries the `__Host-` prefix with the Secure, HttpOnly and SameSite=Lax attributes. With that prefix, leave `Domain` empty and `Path` at `/`, because `New` refuses any other value.
- API keys are read from the `X-Api-Key` header only, never from a URL query parameter.
- Fuzz targets cover password hashes and password checks, cookie settings, API keys, CSRF and opaque tokens, redirect paths, OIDC settings, the rate limiter, and WebAuthn origins and stored credentials.
- `WithBypass` grants a synthetic admin user to every request while its callback returns true. Keep it off in production.
- When hosts you do not control share your relying-party domain, set `RPConfig.Origins` to your own origin. [Passkeys](docs/webauthn.md#narrowing-the-policy-with-origins) explains why.
- Three rules stay with you. Guard every protected route with `RequireAuth`, match your [cookie settings](docs/configuration.md#session-cookie) to where TLS ends, and return a copy of each record your store looks up. [Implementing the store](docs/storage.md) explains the last rule.
- The cryptography has had no independent third-party audit.

Report a vulnerability privately through the [security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md), not in a public issue.

## Unsupported by design

These are left out on purpose. [Non-goals](docs/non-goals.md) gives the reason for each and what to use instead.

- HTTP handlers and a full CSRF middleware, because both depend on your web framework.
- OIDC token refresh, a registry of several providers, back-channel logout and the userinfo endpoint.
- WebAuthn metadata-service verification, attestation conveyance, filtering authenticators by AAGUID, and the passkey well-known endpoints.
- Role hierarchies and permission sets. Each user has one role, and `HasRole` passes when it matches the role a route needs or when the user is an admin.
- Cookie encryption and signing, because the cookie holds only a random token.

The library has no TOTP or SMS second factor. A custom `CredentialVerifier` passed to `WithVerifiers` can add one.

## Documentation

- [Configuration](docs/configuration.md) lists every option and default, the cookie postures and the rate limiter's limits.
- [Passwords, sessions and tokens](docs/primitives.md) covers each building block in detail, OIDC sign-in included.
- [Implementing the store](docs/storage.md) lists the storage interfaces and the rules a store must follow.
- [Passkeys](docs/webauthn.md) explains how ceremonies check origins and what registration requires.
- [Non-goals](docs/non-goals.md) gives the reason for each feature left out.

## Contributing

Issues and pull requests are welcome. The [shared contributing rules](https://github.com/cplieger/.github/blob/main/CONTRIBUTING.md) apply.

## Disclaimer

This project is built with care and follows security best practices, but it is intended for personal / self-hosted use. No guarantees of fitness for production environments. Use at your own risk.

This project was built with AI-assisted tooling using [Claude](https://claude.com), [GPT](https://openai.com), and [Kiro](https://kiro.dev). The human maintainer defines architecture, supervises implementation, and makes all final decisions.

## License

Apache-2.0. See [LICENSE](LICENSE).
