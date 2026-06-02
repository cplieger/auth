package auth

import (
	"log/slog"
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
	logger      *slog.Logger
	bypass      func() bool
	loginPath   string
	cookie      CookieConfig
	idleTimeout time.Duration
	absTimeout  time.Duration
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

// WithLogger sets the logger for debug/warning output.
// If not provided, slog.Default() is used.
func WithLogger(l *slog.Logger) Option {
	return func(c *authConfig) { c.logger = l }
}

// WithBypass sets a function that reports whether authentication is bypassed.
// When the function returns true, all requests are treated as authenticated
// with a synthetic admin user.
func WithBypass(fn func() bool) Option {
	return func(c *authConfig) { c.bypass = fn }
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
