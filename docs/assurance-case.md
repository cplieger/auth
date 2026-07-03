# Security assurance case — auth

This extends the shared
[default assurance case](https://github.com/cplieger/.github/blob/main/assurance-case.md)
with the threat model specific to `auth`. Read that document first for the
shared posture (CI scanning, supply chain, fuzzing, residual risks).

## What this library is

`auth` provides Go authentication primitives: Argon2id password hashing,
session management, API keys, CSRF protection, WebAuthn/passkeys, OIDC + PKCE,
and rate limiting. It is security-critical by definition — it is the thing other
services trust to decide who may act. The HTTP layer is the consumer's job; this
library provides the verified building blocks.

## Top-level claim

`auth` is adequately secure to be the authentication foundation for the
consuming services, against a network attacker who can send arbitrary requests
and observe timing.

## Threats and mitigations

| Threat                                                              | Mitigation                                                   | Evidence                                                                     |
| ------------------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| Offline cracking of stolen password hashes                          | Argon2id with per-user salt and bounded parameters           | `argon2_bounds_test.go`, `hasher.go`                                         |
| Timing side channels on secret comparison                           | constant-time comparison for API keys, tokens, cookies       | `apikey_verifier.go`, `token.go`, dedicated timing tests                     |
| Forged/replayed session cookies                                     | authenticated cookie encoding + validation                   | `auth_cookie.go`, `cookie_validate_test.go`, `cookie_fuzz_test.go`           |
| CSRF                                                                | strict same-origin / token CSRF checks                       | `csrf_strict_test.go`                                                        |
| Malformed input to parsers (PHC strings, cookies, WebAuthn, tokens) | hardened parsing under fuzz                                  | `*_fuzz_test.go`, `parsephc_panic_test.go`, `webauthn/webauthn_fuzz_test.go` |
| Brute-force / credential stuffing                                   | rate limiting (`auth/ratelimit`)                             | rate-limit tests                                                             |
| Adversarial misuse / abuse cases                                    | red-team test suite                                          | `redteam_test.go`, `redteam_fuzz_test.go`                                    |
| Broken crypto choices                                               | only Go stdlib / `golang.org/x/crypto`; no home-grown crypto | source review                                                                |

## Cryptography

Passwords: Argon2id (memory-hard, salted, bounded). Randomness: `crypto/rand`.
OIDC uses PKCE. No deprecated primitives (no MD5/SHA-1 for security purposes).

## Residual risks

- The library cannot enforce that consumers wire it correctly (e.g., actually
  call the verifier, set secure cookie flags); correct integration is the
  consumer's responsibility and is documented in the README.
- No independent third-party cryptographic audit (see the shared default case).

Report vulnerabilities privately per
[SECURITY.md](https://github.com/cplieger/.github/blob/main/SECURITY.md).
