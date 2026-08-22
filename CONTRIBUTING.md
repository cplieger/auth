# Contributing to auth

`auth` is a standalone Go authentication library (`github.com/cplieger/auth`)
providing security primitives: Argon2id password hashing, WebAuthn/FIDO2,
OIDC with PKCE, sessions, API keys, CSRF tokens, and flat RBAC. Because it
sits on the critical path of consumers' login flows, correctness and
constant-time behavior matter more than feature breadth. Read this before
opening a PR.

## Security invariants (don't regress these)

These are the load-bearing guarantees. A change that weakens any of them
needs an explicit `sec:` rationale in the commit body.

- **Constant-time secret comparison.** Every comparison of a
  secret-derived value uses `crypto/subtle.ConstantTimeCompare`, never `==`
  or `bytes.Equal`. This covers password verification (`password.go`,
  `hasher.go`), API-key hash equality (`apikey.go`; this also guards against a
  store doing a loose/prefix lookup), opaque-token verification, and CSRF
  HMAC checks (`token.go`). New verification paths must follow suit.
- **Argon2id OWASP parameters.** The defaults in `password.go` are
  `m=19456` (19 MiB), `t=2`, `p=1`, 16-byte salt, 32-byte key. Hashes are
  PHC strings (`$argon2id$v=19$m=...,t=...,p=...$salt$key`). `NeedsRehash`
  compares against these constants; keep the two in sync. `argon2_bounds_test.go`
  pins the bounds.
- **Login timing equalization.** `DummyHash()` exists so the login handler
  can run a hash for unknown users and avoid a user-enumeration timing
  oracle. Don't short-circuit it.
- **`parsePHC` rejects panic-inducing params.** It refuses `iterations < 1`,
  `parallelism < 1`, and empty keys before they reach `argon2.IDKey` (which
  would otherwise panic). Malformed-input handling here is fuzzed; keep it
  total.
- **Opaque-token model.** Session tokens are 256-bit random values stored as
  SHA-256 hashes; the cookie carries the random token, not sensitive data,
  hence no cookie encryption/signing. CSRF tokens are HMAC-bound to the
  session hash. PKCE uses S256.
- **Safe redirects.** `ValidateRedirectURI` only permits relative paths;
  it strips anything that could become an open redirect.

## Package map

The root package holds the primitives and the persistence-SPI role
interfaces (`UserStore`, `SessionPersister`, `PasskeyStore`, `KeyStore`,
`OIDCStateStore`) the consumer's storage layer implements; subpackages are
independently importable.

| Path                          | Purpose                                                                                                                                                                     |
|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `github.com/cplieger/auth/v4` | Passwords, sessions, tokens, cookies, API keys, WebAuthn/OIDC entry points, middleware/guards (`Authenticator`, `SessionVerifier`, `APIKeyVerifier`, `CredentialVerifier`). |
| `auth/ratelimit`              | Dual sliding-window per-IP + per-account brute-force limiter (OWASP ASVS 2.2.1). Stdlib-only.                                                                               |
| `auth/oidc`                   | OIDC provider config validation and helpers.                                                                                                                                |
| `auth/webauthn`               | WebAuthn/FIDO2 helpers (e.g. AAGUID formatting).                                                                                                                            |
| `auth/authtest`               | Exported in-memory `AuthenticatorStore` (`NewMemStore`, `AddUser`) for consumer tests. Not for production.                                                                  |

Storage is injected by the consumer: the library defines interfaces (the
role interfaces above, `CredentialVerifier`) and never ships a concrete
persistence implementation. Configuration is via functional options only:
no env reads, no global init, no import-time side effects.

### Scope contract

The README "Unsupported Features" table lists deliberate non-goals (full
OIDC token-refresh orchestration, multi-provider registry, hierarchical
RBAC, cookie encryption, full CSRF middleware, etc.). These are binding
decisions, not TODOs; don't implement them without first changing that
table. HTTP handlers are intentionally out of scope; consumers build the
HTTP layer on the exported primitives.

## Local development

Requires the Go toolchain matching `go.mod`.

```sh
go build ./...
go test ./...
```

Run the full suite with the race detector before pushing; concurrency
matters for the rate limiter and the session store:

```sh
go test -race ./...
```

### Lint and format

Linting is enforced in CI via `golangci-lint` (config: `.golangci.yaml`,
v2 schema with `gosec`, `gocritic`, `revive`, `sloglint`, and more).
`golangci-lint run` reports unformatted files as issues, so formatting is
part of the lint gate.

```sh
golangci-lint run
golangci-lint fmt   # applies gofumpt (extra-rules) + gci import ordering
```

Imports are grouped standard → third-party (local module folded in by
gofumpt). `sloglint` is `kv-only`, so use key-value `slog` calls.

### Fuzzing

Parsers and verifiers that touch untrusted input each have a fuzz target.
Targets live beside the code they test and are named `Fuzz*`. Run one for
a bounded time like so:

```sh
# Root package (run from repo root):
go test -run '^$' -fuzz '^FuzzVerifyPassword$' -fuzztime 30s .
go test -run '^$' -fuzz '^FuzzParsePHC$' -fuzztime 30s .
go test -run '^$' -fuzz '^FuzzVerifyCSRFToken$' -fuzztime 30s .
go test -run '^$' -fuzz '^FuzzVerifyOpaqueToken$' -fuzztime 30s .
go test -run '^$' -fuzz '^FuzzVerifyAPIKey$' -fuzztime 30s .
go test -run '^$' -fuzz '^FuzzValidateRedirectURI$' -fuzztime 30s .
go test -run '^$' -fuzz '^FuzzCookieConfigValidate$' -fuzztime 30s .

# Subpackages (one fuzz target per `go test` invocation, scoped to its dir):
go test -run '^$' -fuzz '^FuzzRateLimiterAllow$' -fuzztime 30s ./ratelimit
go test -run '^$' -fuzz '^FuzzOIDCValidateConfig$' -fuzztime 30s ./oidc
go test -run '^$' -fuzz '^FuzzFormatAAGUID$' -fuzztime 30s ./webauthn
```

Other root targets include `FuzzPasswordLengthValidation`,
`FuzzValidatePasswordContext`, `FuzzCSRFTokenRoundTrip`, and
`FuzzValidateCookieField`. `go test` only
runs one `-fuzz` target per package per invocation; the corpus replays as
normal unit tests under `go test ./...`.

### Mutation testing

Test-suite quality is tracked with [Gremlins](https://gremlins.dev)
(config: `.gremlins.yaml`; note `authtest/` is excluded as a test helper).
It runs centrally on a schedule, but you can run it locally:

```sh
gremlins unleash .
```

## Commits and pull requests

Commits follow [Conventional Commits](https://www.conventionalcommits.org/);
git-cliff parses them for release notes and version bumps. Use `feat:`
(minor bump), `fix:` (patch), and **`sec:` for security fixes** (Security
section). `test:`, `fuzz:`, `docs:`, `chore:`, `ci:`, `refactor:`, and
`style:` don't trigger a release (see `cliff.toml`). Write the subject as a
public changelog line.

Branch from `main`, keep changes focused with tests, ensure
`golangci-lint run` and `go test -race ./...` pass locally, and open a PR
against `main`.

## Conduct & security

By participating you agree to the org-wide
[Code of Conduct](https://github.com/cplieger/.github/blob/main/CODE_OF_CONDUCT.md).
Report vulnerabilities through the
[security policy](https://github.com/cplieger/.github/blob/main/SECURITY.md),
never in a public issue.
