package auth

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Default session timeout values matching the pre-refactor struct-field defaults.
const (
	DefaultIdleTimeout = 1 * time.Hour
	DefaultAbsTimeout  = 24 * time.Hour
)

// Option configures an [Authenticator], [SessionVerifier], or [APIKeyVerifier].
type Option func(*authConfig)

// authConfig holds the optional configuration for auth types.
type authConfig struct {
	logger           *slog.Logger
	bypass           func() bool
	unauthorized     func(http.ResponseWriter, *http.Request)
	timeoutSource    func() (idle, abs time.Duration)
	loginPath        string
	verifiers        []CredentialVerifier
	cookie           CookieConfig
	idleTimeout      time.Duration
	absTimeout       time.Duration
	activityThrottle time.Duration
}

// resolveTimeouts returns the effective idle/absolute session timeouts for one
// verification. Without a timeout source (the default) they are the static
// configured values, resolved once at construction. With a source (see
// [WithTimeoutSource]) the source is consulted per call, and each non-positive
// value it returns falls back to the corresponding static configured value, so
// a misbehaving source can never produce the always-expired sessions a
// non-positive timeout would cause (the same hazard the constructors reject
// for static values).
func (c *authConfig) resolveTimeouts() (idle, abs time.Duration) {
	idle, abs = c.idleTimeout, c.absTimeout
	if c.timeoutSource == nil {
		return idle, abs
	}
	di, da := c.timeoutSource()
	if di > 0 {
		idle = di
	}
	if da > 0 {
		abs = da
	}
	return idle, abs
}

// defaults applies default values to unset fields.
func (c *authConfig) defaults() {
	if c.idleTimeout == 0 {
		c.idleTimeout = DefaultIdleTimeout
	}
	if c.absTimeout == 0 {
		c.absTimeout = DefaultAbsTimeout
	}
}

// validate reports whether the assembled configuration is usable. The
// constructors call it after options and defaults are applied so an unusable
// configuration fails fast at construction rather than silently breaking at
// request time. Call defaults before validate: the activity-throttle check
// compares against the resolved idle timeout.
func (c *authConfig) validate() error {
	if err := c.cookie.Validate(); err != nil {
		return err
	}
	// Timeouts must be positive. defaults() substitutes the package defaults
	// only for a zero value, so a negative duration passed via WithIdleTimeout
	// or WithAbsTimeout would otherwise survive to request time — where a
	// negative idle timeout makes every session expire immediately
	// (now.Sub(lastActivity) > negative is always true), a silently broken
	// authenticator. Fail fast at construction instead.
	if c.idleTimeout <= 0 {
		return fmt.Errorf("auth: idle timeout must be positive, got %s", c.idleTimeout)
	}
	if c.absTimeout <= 0 {
		return fmt.Errorf("auth: absolute timeout must be positive, got %s", c.absTimeout)
	}
	// The persisted last-activity timestamp is refreshed at most once per
	// throttle window, so it lags real activity by up to that window. A
	// throttle at or above the idle timeout therefore lets ValidateSession
	// expire sessions that are still actively in use. A zero throttle (the
	// default) disables throttling and is always valid.
	if c.activityThrottle > 0 && c.activityThrottle >= c.idleTimeout {
		return fmt.Errorf("auth: activity throttle (%s) must be less than the idle timeout (%s)", c.activityThrottle, c.idleTimeout)
	}
	return nil
}

// WithLogger sets the logger for debug/warning output.
// If not provided, slog.Default() is used.
func WithLogger(l *slog.Logger) Option {
	return func(c *authConfig) { c.logger = l }
}

// WithBypass sets a function that reports whether authentication is bypassed.
// When the function returns true, all requests are treated as authenticated
// with a synthetic admin user. Installing the hook logs one Info line at
// construction; the loud production-safety WARN fires once, on the first
// request the hook actually grants — an installed-but-inactive hook (the
// common hot-reloadable dev-flag shape) therefore never warns.
func WithBypass(fn func() bool) Option {
	return func(c *authConfig) { c.bypass = fn }
}

// WithUnauthorizedResponse sets the response written by
// [Authenticator.RequireAuth] when a request is not authenticated, replacing
// the default behavior (a 302 redirect to the login path for browser requests,
// a 401 JSON envelope otherwise). The hook owns the entire unauthorized
// response: it is called for browser and API requests alike, so a consumer
// that wants to keep the browser redirect applies [IsBrowserRequest] itself.
// A nil hook (the default) preserves the built-in behavior byte for byte.
func WithUnauthorizedResponse(fn func(w http.ResponseWriter, r *http.Request)) Option {
	return func(c *authConfig) { c.unauthorized = fn }
}

// WithTimeoutSource sets a callback that resolves the session idle and
// absolute timeouts per verification, instead of the static values configured
// via [WithIdleTimeout]/[WithAbsTimeout]. It exists for consumers whose
// timeouts are hot-reloadable configuration: the default [SessionVerifier]
// consults the source on every Verify, so a changed value takes effect without
// reconstructing the verifier.
//
// Validation is per-resolution (a construction-time check cannot bind dynamic
// values): a non-positive idle or absolute value returned by the source falls
// back to the corresponding static configured value, and the activity throttle
// (see [WithActivityThrottle]) is clamped to at most half the resolved idle
// timeout, so a source that shrinks the idle timeout below the configured
// throttle can never make the persisted LastActivity stale enough to expire a
// session that is actively in use.
func WithTimeoutSource(fn func() (idle, abs time.Duration)) Option {
	return func(c *authConfig) { c.timeoutSource = fn }
}

// WithLoginPath sets the redirect target for unauthenticated browser requests.
// Defaults to "/login".
func WithLoginPath(path string) Option {
	return func(c *authConfig) { c.loginPath = path }
}

// WithCookie sets the cookie configuration for session cookies.
func WithCookie(cfg CookieConfig) Option {
	return func(c *authConfig) { c.cookie = cfg }
}

// WithIdleTimeout sets the session idle timeout duration.
func WithIdleTimeout(d time.Duration) Option {
	return func(c *authConfig) { c.idleTimeout = d }
}

// WithAbsTimeout sets the session absolute timeout duration.
func WithAbsTimeout(d time.Duration) Option {
	return func(c *authConfig) { c.absTimeout = d }
}

// WithActivityThrottle sets the minimum interval between session-activity
// writes for a given session within a [SessionVerifier].
//
// The default (d == 0) preserves write-on-every-authenticated-request
// behavior. When d > 0, the verifier records a session-activity write at most
// once per d per session hash, coalescing the high-frequency writes that would
// otherwise hit the store on every request. The write remains best-effort
// (errors are logged, never fatal).
//
// d must be less than the configured idle timeout (ideally much less): because
// the persisted LastActivity is only refreshed once per window, it lags real
// activity by up to d, so a throttle >= the idle timeout can cause
// ValidateSession to expire sessions that are actively in use. The
// constructors reject such a configuration with an error.
func WithActivityThrottle(d time.Duration) Option {
	return func(c *authConfig) { c.activityThrottle = d }
}

// WithVerifiers sets an explicit, ordered credential-verifier chain for an
// [Authenticator], replacing the default session + API-key chain. When the
// provided slice is empty (or this option is not used), the default chain is
// used. This lets consumers inject custom verifiers (e.g. a TOTP or
// app-specific session verifier) without copying Authenticate; a consumer that
// also needs its own unauthorized response pairs it with
// [WithUnauthorizedResponse] to keep RequireAuth.
func WithVerifiers(vs []CredentialVerifier) Option {
	return func(c *authConfig) { c.verifiers = vs }
}

// HasherOption configures a [Hasher].
type HasherOption func(*hasherConfig)

// hasherConfig holds the optional configuration for a Hasher.
type hasherConfig struct {
	pepper []byte
}

// WithPepper sets the HMAC pepper applied to passwords before hashing.
// If not provided, no pepper is applied.
func WithPepper(pepper []byte) HasherOption {
	return func(c *hasherConfig) { c.pepper = pepper }
}
