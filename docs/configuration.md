# Configuration

This page lists every option of `auth.New`, the session cookie settings, the password hasher's parameters and the rate limiter's limits, with their defaults. Read it when you set up an `Authenticator` for your service.

Every setting is a functional option or a function argument. The library reads no environment variables, keeps every setting on the value you construct and does nothing when it is imported.

## Authenticator options

`New` and `NewSessionVerifier` take these options. `NewAPIKeyVerifier` reads only `WithLogger`.

| Option | What it sets | Default |
| --- | --- | --- |
| `WithLogger(l)` | The `*slog.Logger` for warnings and debug lines | `slog.Default()` |
| `WithLoginPath(path)` | Where `RequireAuth` redirects a browser that is not signed in | `/login` |
| `WithCookie(cfg)` | The session cookie, described below | the zero `CookieConfig`, which behaves as `DefaultCookieConfig()` |
| `WithIdleTimeout(d)` | How long a session may sit unused | 1h |
| `WithAbsTimeout(d)` | How long a session may live at most | 24h |
| `WithActivityThrottle(d)` | Writes session activity at most once per `d` for each session | `0`, a write on every request |
| `WithTimeoutSource(fn)` | Reads the two timeouts from a callback on every verification, for settings you reload at run time | _(unset)_ |
| `WithUnauthorizedResponse(fn)` | Replaces the response `RequireAuth` writes for a request that is not signed in | _(unset)_ |
| `WithVerifiers(vs)` | Replaces the verifier chain with your own `CredentialVerifier` list | the session cookie, then the API key |
| `WithBypass(fn)` | A development hook that grants a synthetic admin user while `fn` returns true | _(unset)_ |

`New` and `NewSessionVerifier` return an error for a configuration that cannot work. That is a timeout at or below zero, an activity throttle at or above the idle timeout, or a cookie configuration that `CookieConfig.Validate` refuses.

The activity throttle exists to cut store writes. The stored last-activity time lags real activity by up to one throttle window, which is why the throttle must stay below the idle timeout.

With `WithTimeoutSource`, a value at or below zero from the callback falls back to the matching static option. The activity throttle is then capped at half the resolved idle timeout, so a shorter idle timeout cannot expire a session that is in use.

By default `RequireAuth` answers a browser with a 302 redirect to the login path, with the requested path in a `next` query parameter, and any other client with a 401 JSON body. A `WithUnauthorizedResponse` hook replaces both answers. Call `IsBrowserRequest` inside it to keep a redirect for browsers.

`WithBypass` logs one info line when it is installed. It logs a warning once, on the first request it actually grants. Keep it off in production.

## Session cookie

`CookieConfig` holds the cookie's attributes. Declare the configuration your deployment needs instead of relying on a default, so the posture is visible where you call `New`.

| Field | What it sets | Default |
| --- | --- | --- |
| `Name` | The base cookie name, without the `__Host-` prefix | `auth_session` |
| `Posture` | The prefix and Secure flag strategy, in the next table | `PostureSecure` |
| `Path` | The cookie's Path attribute | `/` |
| `Domain` | The cookie's Domain attribute | _(unset)_ |
| `SameSite` | The cookie's SameSite attribute | `http.SameSiteLaxMode` |
| `TrustForwardedHeaders` | Reads `X-Forwarded-Proto` to tell whether a request arrived over HTTPS | `false` |

```go
cfg := auth.CookieConfig{
	Name:     "my_session",
	Posture:  auth.PostureSecure,
	Path:     "/",
	Domain:   "", // must stay empty under a __Host- posture
	SameSite: http.SameSiteLaxMode,
	// TrustForwardedHeaders: true, // only behind a proxy that always sets X-Forwarded-Proto
}
authenticator, err := auth.New(myStore, auth.WithCookie(cfg))
if err != nil {
	log.Fatalf("auth: %v", err) // CookieConfig.Validate refused cfg
}
```

| Posture | Behavior |
| --- | --- |
| `PostureSecure` | The default. The `__Host-` prefix with Secure, HttpOnly and SameSite=Lax, for any HTTPS deployment, self-signed certificates included |
| `PostureInsecureLAN` | For plain-HTTP access by address and port on a LAN or a Docker network. The bare name without Secure, chosen only explicitly |
| `PostureForceSecure` | The `__Host-` prefix with Secure on every response, whatever the request scheme. It suits a TLS-terminating proxy, where the request itself carries no TLS state |
| `PosturePerRequest` | Over HTTPS, the `__Host-` prefix with Secure. Over plain HTTP, the bare name without Secure. Honors `TrustForwardedHeaders` |

`PosturePerRequest` suits one instance that serves both plain-HTTP LAN traffic and HTTPS traffic through a proxy.

Every posture except `PostureInsecureLAN` uses the `__Host-` prefix. Under those, `Domain` must stay empty and `Path` must be `/`, because browsers silently drop a `__Host-` cookie that breaks either rule. `Validate` refuses such a configuration, and it also refuses control characters in the name, domain and path.

Enable `TrustForwardedHeaders` only behind a reverse proxy that always sets or overwrites `X-Forwarded-Proto`. When it is false, only the request's own TLS state counts.

`SetCookie` always sets HttpOnly and also sends `Cache-Control: no-store`. `ClearCookie` expires the cookie, and `ReadCookie` reads the name that fits the request.

## Password hasher

`HashPassword`, `VerifyPassword` and `NeedsRehash` use `DefaultArgon2Params()`: 19456 KiB of memory, 2 iterations, 1 thread, a 16-byte salt and a 32-byte key. Each hash is a PHC string such as `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.

`NewHasher` takes your own `Argon2Params` and an optional `WithPepper` for an HMAC pepper:

```go
hasher, err := auth.NewHasher(auth.Argon2Params{
	Memory: 65536, Iterations: 3, Parallelism: 2,
	SaltLength: 16, KeyLength: 32,
}, auth.WithPepper([]byte("my-secret-pepper")))
if err != nil {
	log.Fatal(err) // a parameter is out of bounds
}
hash := hasher.Hash("my-secure-password")
ok, err := hasher.Verify("my-secure-password", hash)
```

`NewHasher` refuses memory below 1024 KiB or above 4 GiB, iterations below 1 or above 100, parallelism below 1, a salt shorter than 8 bytes and a key shorter than 16 bytes.

`NeedsRehash` reports a hash made with other parameters, so you can rehash the password at the user's next sign-in.

## Rate limiter

`ratelimit.DefaultConfig()` allows 10 attempts per IP address in 15 minutes and 100 attempts per account in one hour. It tracks up to 10,000 entries and prunes them every 5 minutes. The two sliding windows follow OWASP ASVS 2.2.1. The package uses only the standard library. Its two keys are separate types, `ClientIP` and `Username`, so the compiler stops you from swapping them.

| Field | Default |
| --- | --- |
| `IPLimit` | 10 |
| `IPWindow` | 15m |
| `AcctLimit` | 100 |
| `AcctWindow` | 1h |
| `PruneInterval` | 5m |
| `MaxEntries` | 10000 |

`New` replaces a window, a prune interval or an entry cap at or below zero with its default and logs a warning. It keeps a limit at or below zero as given and logs a warning, because such a limit blocks every request after the first recorded attempt.

`Allow` skips a dimension whose key is empty, so pass the client's real IP address for the per-IP limit to apply. The prune goroutine stops when the context given to `New` ends. `Shutdown` stops it and blocks until it has exited, or until the context given to `Shutdown` ends.
