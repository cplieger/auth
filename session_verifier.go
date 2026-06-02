package auth

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// SessionVerifier authenticates requests via session cookie.
// Create with [NewSessionVerifier].
type SessionVerifier struct {
	store SessionStore
	cfg   authConfig
}

// NewSessionVerifier creates a SessionVerifier with the given session store and options.
// If no idle/absolute timeout is provided, defaults of 1h and 24h are applied.
func NewSessionVerifier(store SessionStore, opts ...Option) *SessionVerifier {
	cfg := authConfig{}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	cfg.defaults()
	return &SessionVerifier{store: store, cfg: cfg}
}

// logger returns the configured logger or slog.Default().
func (v *SessionVerifier) logger() *slog.Logger {
	if v.cfg.logger != nil {
		return v.cfg.logger
	}
	return slog.Default()
}

// Verify checks the session cookie and returns the user if valid.
func (v *SessionVerifier) Verify(ctx context.Context, r *http.Request) (*User, string, error) {
	token := v.cfg.cookie.ReadCookie(r)
	if token == "" {
		return nil, "", nil
	}
	hash := SessionHash(token)
	sess, err := v.store.GetSessionByHash(ctx, hash)
	if err != nil {
		v.logger().Debug("auth: session lookup failed", "error", err)
		return nil, "", nil
	}
	if sess == nil {
		return nil, "", nil
	}
	now := time.Now()
	if ValidateSession(sess, v.cfg.idleTimeout, v.cfg.absTimeout, now) != nil {
		return nil, "", nil
	}
	if actErr := v.store.UpdateSessionActivity(ctx, hash, now); actErr != nil {
		v.logger().Warn("auth: session activity update failed", "error", actErr)
	}
	user, err := v.store.GetUserByID(ctx, sess.UserID)
	if err != nil {
		v.logger().Debug("auth: user lookup failed", "user_id", sess.UserID, "error", err)
		return nil, "", nil
	}
	if user == nil || !user.Enabled {
		if user != nil {
			v.logger().Debug("auth: disabled user attempted session auth", "user_id", sess.UserID)
		}
		return nil, "", nil
	}
	return user, hash, nil
}
