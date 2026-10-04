# Passwords, sessions and tokens

This page explains each building block of the root package and of the `oidc` package. For each one it says what it does, what it returns and the rule a caller must keep. Read it when you write the handlers around them. Signatures are on [pkg.go.dev](https://pkg.go.dev/github.com/cplieger/auth/v6), and the defaults are on the [Configuration](configuration.md) page.

## Passwords

`HashPassword` hashes a password with Argon2id and returns a PHC string, with no error. `VerifyPassword` checks a password against a stored hash, and `NeedsRehash` reports a hash made with other parameters. `Hasher.Hash`, `Hasher.Verify` and `Hasher.NeedsRehash` do the same with your own parameters and an optional pepper.

`DummyHash` returns a fixed Argon2id hash. When the username does not exist, verify the password against it, so an unknown username takes as long to refuse as a wrong password.

`ValidateMultiFactorPasswordLength` requires at least 8 characters, for an account where the password is not the only factor. `ValidateSoloPasswordLength` requires at least 15, for an account where the password alone grants access. Both allow 128 characters at most.

`ValidatePasswordContext` refuses a password that contains any of the forbidden words, or the username when the username has four characters or more. Its zero `PasswordContext` checks nothing at all, so fill every field the account has.

`CheckBreachedPassword` asks the Have I Been Pwned Passwords API whether a password appears in a breach. It sends only the first five characters of the password's SHA-1 hash, the k-anonymity range request. When the API cannot be reached or answers with an error, it logs a warning and allows the password.

## Usernames

`NormalizeUsername` decides whether two usernames are the same account. It applies the `UsernameCaseMapped` profile of the PRECIS IdentifierClass from RFC 8265, a standard rule for comparing usernames.

- Case folds across the whole of Unicode, so `Müller` and `MÜLLER` are one account.
- Nothing is transliterated, so `straße` and `strasse` stay two accounts.
- A username containing a space is refused. The characters `.`, `-` and `_` are allowed.
- An empty result returns `ErrUsernameEmpty`, and a refused character returns `ErrUsernameInvalid`.

Apply it on both sides of the comparison. Apply it to the key of your unique-username index, and again to the login input before the lookup.

## Sessions

`GenerateSessionToken` returns a 256-bit random token and its SHA-256 hash, with no error. Put the token in the cookie and store only the hash. `SessionHash` turns the cookie value back into the hash you look up.

`RotateSessionToken` returns a new token, its hash and the old token's hash. Replace the stored session in one step. Delete the old hash and insert the new one with the same session data.

`ValidateSession` checks a session against a `SessionTimeouts` value holding the idle and absolute timeouts, and against the OIDC token's expiry when the session has one. Fill both timeouts. A zero field expires every session, so a mistake locks users out instead of letting them in.

The session verifier inside `Authenticator` refuses a session whose user is disabled or missing.

## CSRF and one-time tokens

`CSRFToken` makes a token bound to a session hash, signed with HMAC-SHA256 under your key with a random 16-byte nonce. `VerifyCSRFToken` checks the signature against the session hash and refuses a token older than the maximum age you pass. An empty key is an error for both.

`GenerateOpaqueToken` returns a random token and its SHA-256 hash, for password-reset and email-verification links. Send the token to the user and store the hash. `VerifyOpaqueToken` checks a token against the stored hash and its expiry time, and returns `ErrTokenInvalid` or `ErrTokenExpired`.

## API keys

`GenerateAPIKey` returns a key with your prefix in front of 256 random bits, its SHA-256 hash, and the first 8 and last 4 characters for display. Store the hash and show the key once.

`VerifyAPIKey` hashes a key, looks it up in your store, compares the stored hash in constant time and checks the expiry. A missing, mismatched or expired key returns `ErrInvalidAPIKey`. `Key.ExpiresAt` left at its zero value means the key never expires.

The `Authenticator` reads an API key from the `X-Api-Key` header only. A key in a URL query parameter ends up in server logs and browser history, CWE-598, so it is never accepted.

## Guards

`Authenticator.Authenticate` returns the user for a request, or `ErrUnauthenticated`. `RequireAuth` does the same and writes the refusal for you.

`HasRole` checks a user's role. The two roles are `RoleUser` and `RoleAdmin`, and an admin passes every role check.

`ValidateRedirectURI` returns the path you pass when it is a safe relative path, and `/` for anything else. Pass the `next` value from a sign-in form through it before you redirect.

`CanDisableMethod` reports whether a user keeps at least one way to sign in after you turn one off. It takes a `MethodAvailability` value with the passkey count, the password and the OIDC link, and its zero value refuses every change.

`IsBrowserRequest` reports a request whose `Accept` header contains `text/html` and that carries no `X-Api-Key` header.

## OIDC sign-in

The `oidc` package signs a user in with an OpenID Connect provider, on [coreos/go-oidc](https://github.com/coreos/go-oidc).

1. `ValidateConfig` checks an `oidc.Config`, and `NewProvider` discovers the provider's endpoints.
2. `GenerateState` and `GeneratePKCE` make the state value and the PKCE S256 verifier and challenge. The nonce is yours to make, a single-use random value. Save the state, the nonce, the verifier and the redirect path with `OIDCStateStore.CreateOIDCState`.
3. `Provider.AuthorizationURL` builds the URL to send the browser to. It refuses an empty state or code challenge.
4. When the browser returns, read the nonce and the verifier back with `ConsumeOIDCState`. `Provider.Exchange` trades the code for tokens, verifies the ID token and requires its nonce to equal yours. An empty or different nonce returns `ErrNonceMismatch`. It also returns the token's expiry, zero when the provider sent none.
5. Look up the user with `UserStore.UserByOIDCSub`, using the token's issuer and subject, and pass the result to `ResolveUser`. For a new identity it returns an unsaved user with `isNew` set, which you store with `CreateUser`. It returns `ErrNoUsername` when that new identity's token has neither a `preferred_username` nor an `email` claim.

`State`, `Nonce`, `CodeChallenge`, `Code` and `CodeVerifier` are separate string types, so the compiler stops you from passing one where another belongs. `State`, `Nonce` and `CodeVerifier` are the same types as the root package's `OIDCState`, `OIDCNonce` and `OIDCCodeVerifier`, which `OIDCStateStore` uses.
