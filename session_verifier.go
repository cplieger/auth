package auth

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// SessionVerifierStore is the minimal interface for session verification.
type SessionVerifierStore interface {
	SessionReader
	SessionActivityUpdater
	UserReader
}

// SessionVerifier authenticates requests via session cookie.
// Create with [NewSessionVerifier].
type SessionVerifier struct {
	store        SessionVerifierStore
	lastActivity map[string]time.Time
	cfg          authConfig
	activityMu   sync.Mutex
}

// NewSessionVerifier creates a SessionVerifier with the given session store and
// options. It returns an error when the assembled configuration is unusable:
// for example a __Host- cookie posture combined with a Domain or a non-root
// Path (which browsers reject), or an activity throttle that is not less than
// the idle timeout. See [CookieConfig.Validate]. If no idle/absolute timeout is
// provided, defaults of 1h and 24h are applied.
func NewSessionVerifier(store SessionVerifierStore, opts ...Option) (*SessionVerifier, error) {
	cfg := authConfig{}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &SessionVerifier{
		store:        store,
		cfg:          cfg,
		lastActivity: make(map[string]time.Time),
	}, nil
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
		v.logger().Warn("auth: session lookup failed", "error", err)
		return nil, "", nil
	}
	if sess == nil {
		return nil, "", nil
	}
	now := time.Now()
	// Timeouts are resolved per verification so a WithTimeoutSource consumer's
	// hot-reloaded values take effect immediately; without a source this is
	// exactly the static configured pair.
	idle, abs := v.cfg.resolveTimeouts()
	if verr := ValidateSession(sess, idle, abs, now); verr != nil {
		v.logger().Debug("auth: session rejected", "user_id", sess.UserID, "reason", verr)
		return nil, "", nil
	}
	if v.shouldWriteActivity(hash, now, idle) {
		if actErr := v.store.UpdateSessionActivity(ctx, hash, now); actErr != nil {
			v.logger().Warn("auth: session activity update failed", "error", actErr)
		}
	}
	user, err := v.store.GetUserByID(ctx, sess.UserID)
	if err != nil {
		v.logger().Warn("auth: user lookup failed", "user_id", sess.UserID, "error", err)
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

// activityPruneThreshold is the lastActivity map size beyond which stale
// entries (older than the throttle window) are pruned to bound memory growth.
const activityPruneThreshold = 1024

// shouldWriteActivity reports whether a session-activity write should be issued
// for the given session hash at time now, given the idle timeout resolved for
// this verification.
//
// When the configured throttle is 0 (the default), it always returns true,
// preserving write-on-every-request behavior with no locking. When the
// throttle d > 0, it returns true at most once per d per session hash, using a
// concurrency-safe per-hash last-write map. The decision time is recorded as
// the last-write time so concurrent callers within the same window collapse to
// a single write.
//
// The effective throttle is clamped to at most idle/2. Construction validates
// throttle < idle only against the static configured idle timeout; a
// WithTimeoutSource consumer can resolve a smaller idle at runtime, and an
// unclamped throttle at or above it would let the persisted LastActivity lag
// far enough for ValidateSession to expire sessions that are actively in use.
// The clamp errs toward more writes — the safe direction.
func (v *SessionVerifier) shouldWriteActivity(hash string, now time.Time, idle time.Duration) bool {
	d := v.cfg.activityThrottle
	if d <= 0 {
		return true
	}
	if half := idle / 2; d > half {
		d = half
		if d <= 0 {
			return true
		}
	}
	v.activityMu.Lock()
	defer v.activityMu.Unlock()
	if last, ok := v.lastActivity[hash]; ok && now.Sub(last) < d {
		return false
	}
	v.lastActivity[hash] = now
	v.pruneActivityLocked(now, d)
	return true
}

// pruneActivityLocked removes last-write entries older than the throttle window
// to bound the map's growth. Entries older than d would permit a write on the
// next request regardless, so dropping them is behavior-preserving. Pruning is
// skipped until the map exceeds activityPruneThreshold to keep the common path
// cheap. Callers must hold activityMu.
func (v *SessionVerifier) pruneActivityLocked(now time.Time, d time.Duration) {
	if len(v.lastActivity) < activityPruneThreshold {
		return
	}
	for h, t := range v.lastActivity {
		if now.Sub(t) >= d {
			delete(v.lastActivity, h)
		}
	}
}
