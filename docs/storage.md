# Implementing the store

auth stores nothing itself. This page lists the interfaces your storage layer implements and the rules each one must follow, for the developer writing that layer. Method signatures are on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/auth/v6).

## The interfaces

Implement only the roles your handlers use.

| Interface | What it holds |
| --- | --- |
| `UserStore` | Accounts, looked up by ID, username, email, OIDC subject and WebAuthn handle |
| `SessionPersister` | Sessions, looked up by token hash, with activity updates and cleanup |
| `PasskeyStore` | Passkeys per user, with the update each login writes |
| `KeyStore` | API keys, looked up by hash |
| `OIDCStateStore` | The single-use state, nonce and PKCE verifier of each OIDC sign-in |

`auth.New` takes an `AuthenticatorStore`, the read side it needs. That is session lookup and activity updates, user lookup by ID, and API-key lookup by hash. `webauthn.CompleteLogin` takes a `webauthn.Store`, which a type implementing `UserStore` and `PasskeyStore` already satisfies.

## Rules every lookup follows

A lookup by key returns `(value, found, err)`. Absence is `found == false` with a nil error, never a nil value with a nil error, and never an error. A list method is a search instead, and an empty slice with a nil error is its correct answer.

A lookup returns a value the caller owns. Never hand back a pointer to state the store keeps changing. Never keep reading a pointer the caller passed to a write method after the method returns. The library reads a returned session after the lookup, while another request may update the same session. A shared pointer there is a data race that no lock inside the store can fix. A store that scans each query into a fresh value meets this rule already. An in-memory or caching store must copy.

## Usernames

Apply `NormalizeUsername` on both sides of the comparison. Apply it once to build the unique-username index key, and again to the login input before `UserByUsername` looks it up. Applied to one side only, a user who registered as `Alex` cannot sign in as `alex`.

A store that already holds usernames changes its index key when it adopts this rule. Scan the stored values first for two cases. The first is a username `NormalizeUsername` now refuses, whose owner cannot sign in until it is renamed. The second is a pair that differed under a plain ASCII lowercase and now collides.

## WebAuthn handles and passkey flags

`User.WebAuthnHandle` is the value an authenticator stores to identify the account. Set it with `GenerateWebAuthnHandle`, 64 random bytes, when you create the account, and never change it, because every registered passkey is bound to it. Persist it and index it, because a discoverable login arrives carrying only the handle.

`UserByWebAuthnHandle` must answer the same way for an unknown handle and a malformed one. A different answer would let someone who is not signed in probe which handles exist.

`PasskeyCredential.RawFlags` is required, and it is the only flag field the library reads. The four booleans beside it are a decoded view for display. A store that drops the octet restores each passkey with every flag false. Every login with a synced passkey then fails, because the stored backup-eligible flag no longer matches what the authenticator reports. A store that kept only the booleans can rebuild the octet. User presence is bit 0, user verification bit 2, backup eligibility bit 3 and backup state bit 4.

## Sessions

`CleanupExpiredSessions` takes a `SessionTimeouts` value. Fill both fields, because a zero value treats every session as expired and deletes every row.

## The test store

`authtest.NewMemStore` returns an in-memory `AuthenticatorStore` for your tests. Every read returns a copy and every write stores one, so a test can change what it receives without touching the store. It is meant for tests only.

```go
store := authtest.NewMemStore()
store.AddUser(&auth.User{Username: "test", Role: auth.RoleUser, Enabled: true})
```
