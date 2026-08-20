package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cplieger/auth/v4/internal/capture"
)

// newVerifierRequest builds a request carrying the session cookie for the
// default cookie configuration.
func newVerifierRequest(t *testing.T, plaintext string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	cfg := DefaultCookieConfig()
	r.AddCookie(&http.Cookie{Name: cfg.EffectiveName(), Value: plaintext})
	return r
}

// newVerifierSession creates a user (enabled or disabled) with a live session
// and returns the store and the session plaintext token.
func newVerifierSession(t *testing.T, enabled bool) (*fakeSessionStore, string) {
	t.Helper()
	store := newFakeSessionStore()
	ctx := t.Context()
	user := &User{Username: "alice", Role: RoleAdmin, Enabled: enabled}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	now := time.Now()
	if err := store.CreateSession(ctx, &Session{TokenHash: hash, UserID: user.ID, CreatedAt: now, LastActivity: now}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return store, plaintext
}

func TestSessionVerifier_Verify_successfulActivityUpdate_logsNoWarning(t *testing.T) {
	t.Parallel()

	// A live session whose activity update succeeds must not log the
	// activity-update warning.
	logger, h := capture.New()
	store, plaintext := newVerifierSession(t, true)
	v := mustSessionVerifier(t, store, WithLogger(logger), WithCookie(DefaultCookieConfig()))

	gotUser, _, err := v.Verify(t.Context(), newVerifierRequest(t, plaintext))
	if err != nil || gotUser == nil {
		t.Fatalf("Verify() = (%v, %v), want a valid user and nil error", gotUser, err)
	}
	if n := h.CountMsg("session activity update failed"); n != 0 {
		t.Errorf("Verify() with successful activity update logged %d activity-update warnings, want 0", n)
	}
}

func TestSessionVerifier_Verify_disabledUser_refusesAndLogs(t *testing.T) {
	t.Parallel()

	// A disabled user with an otherwise-valid session must be refused, and the
	// attempt must be logged at debug level.
	logger, h := capture.New()
	store, plaintext := newVerifierSession(t, false)
	v := mustSessionVerifier(t, store, WithLogger(logger), WithCookie(DefaultCookieConfig()))

	gotUser, _, err := v.Verify(t.Context(), newVerifierRequest(t, plaintext))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if gotUser != nil {
		t.Fatalf("Verify() = %v, want nil (disabled user)", gotUser)
	}
	if n := h.CountMsg("disabled user attempted session auth"); n != 1 {
		t.Errorf("Verify() with disabled user logged %d disabled-user debug records, want 1", n)
	}
}

func TestSessionVerifier_Verify_idleTimeoutOption_expiresOldSession(t *testing.T) {
	t.Parallel()

	// A session last active 2h ago is expired under a 1h idle timeout (no auth)
	// but valid under a 3h idle timeout. This pins the idle-timeout option as
	// the deciding input through the public Verify path.
	ctx := t.Context()
	store := newFakeSessionStore()
	user := &User{Username: "timeuser", PasswordHash: "x", Role: RoleUser, Enabled: true}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	plain, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := store.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: MethodPassword,
		IPAddress: "1.2.3.4", CreatedAt: past, LastActivity: past,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: plain})

	// The subtests run in order and share the store; only the accepting
	// verifier writes activity, and it runs second, so the rejection subtest
	// always sees the original 2h-stale LastActivity.
	t.Run("1h idle timeout rejects a 2h-idle session", func(t *testing.T) {
		expired := mustSessionVerifier(t, store, WithCookie(cfg), WithIdleTimeout(time.Hour))
		if u, _, _ := expired.Verify(ctx, r); u != nil {
			t.Errorf("Verify() with 1h idle timeout = %+v, want nil (session idle for 2h)", u)
		}
	})
	t.Run("3h idle timeout accepts a 2h-idle session", func(t *testing.T) {
		valid := mustSessionVerifier(t, store, WithCookie(cfg), WithIdleTimeout(3*time.Hour))
		if u, _, _ := valid.Verify(ctx, r); u == nil {
			t.Error("Verify() with 3h idle timeout = nil, want a user")
		}
	})
}

// --- shouldWriteActivity: per-hash activity-write throttling decision ---

func TestSessionVerifier_shouldWriteActivity_zeroThrottle_writesWithoutRecording(t *testing.T) {
	t.Parallel()

	// With the throttle disabled (d == 0, the default) every request writes and
	// nothing is recorded in the lastActivity map (the no-lock fast path).
	v := &SessionVerifier{
		lastActivity: make(map[string]time.Time),
		cfg:          authConfig{activityThrottle: 0},
	}

	if !v.shouldWriteActivity("hash", time.Now(), DefaultIdleTimeout) {
		t.Errorf("shouldWriteActivity(throttle=0) = false, want true")
	}
	if n := len(v.lastActivity); n != 0 {
		t.Errorf("shouldWriteActivity(throttle=0) recorded %d entries, want 0", n)
	}
}

func TestSessionVerifier_shouldWriteActivity_elapsedEqualsThrottle_writes(t *testing.T) {
	t.Parallel()

	// When exactly the throttle window has elapsed since the last write, the
	// next write is NOT throttled (the window boundary is exclusive on the low
	// side: a write is suppressed only while elapsed is strictly less than d).
	const d = 30 * time.Minute
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	v := &SessionVerifier{
		lastActivity: map[string]time.Time{"hash": t0},
		cfg:          authConfig{activityThrottle: d},
	}

	// idle is 4*d so the idle/2 clamp is inactive and the raw window boundary
	// is what this test pins.
	if !v.shouldWriteActivity("hash", t0.Add(d), 4*d) {
		t.Errorf("shouldWriteActivity(elapsed == throttle) = false, want true")
	}
}

// --- pruneActivityLocked: bounded growth of the last-write map ---

func TestSessionVerifier_pruneActivityLocked_ageEqualsThrottle_deletes(t *testing.T) {
	t.Parallel()

	// An entry whose age equals the throttle window is already stale (a write
	// would be permitted again), so pruning must delete it: the staleness
	// boundary is inclusive at exactly d.
	const d = time.Minute
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	const boundaryKey = "boundary"
	m := make(map[string]time.Time, activityPruneThreshold)
	m[boundaryKey] = now.Add(-d) // age exactly d
	for i := range activityPruneThreshold - 1 {
		m[fmt.Sprintf("old%d", i)] = now.Add(-time.Hour)
	}

	v := &SessionVerifier{lastActivity: m, cfg: authConfig{activityThrottle: d}}
	v.activityMu.Lock()
	v.pruneActivityLocked(now, d)
	v.activityMu.Unlock()

	if _, ok := v.lastActivity[boundaryKey]; ok {
		t.Errorf("pruneActivityLocked kept the entry aged exactly the throttle window, want it deleted")
	}
}

func TestSessionVerifier_pruneActivityLocked_atThreshold_prunesStale(t *testing.T) {
	t.Parallel()

	// Pruning runs once the map size reaches the threshold; a map of exactly
	// activityPruneThreshold all-stale entries is emptied.
	const d = time.Minute
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	stale := now.Add(-time.Hour)

	m := make(map[string]time.Time, activityPruneThreshold)
	for i := range activityPruneThreshold {
		m[fmt.Sprintf("k%d", i)] = stale
	}

	v := &SessionVerifier{lastActivity: m, cfg: authConfig{activityThrottle: d}}
	v.activityMu.Lock()
	v.pruneActivityLocked(now, d)
	v.activityMu.Unlock()

	if n := len(v.lastActivity); n != 0 {
		t.Errorf("pruneActivityLocked(at threshold, all stale) left %d entries, want 0", n)
	}
}

func TestSessionVerifier_pruneActivityLocked_belowThreshold_keepsAll(t *testing.T) {
	t.Parallel()

	// Below the threshold pruning is skipped entirely to keep the common path
	// cheap, so even a stale entry survives.
	const d = time.Minute
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	m := map[string]time.Time{
		"stale": now.Add(-time.Hour),
		"fresh": now,
	}
	v := &SessionVerifier{lastActivity: m, cfg: authConfig{activityThrottle: d}}
	v.activityMu.Lock()
	v.pruneActivityLocked(now, d)
	v.activityMu.Unlock()

	if n := len(v.lastActivity); n != 2 {
		t.Errorf("pruneActivityLocked(below threshold) left %d entries, want 2 (no pruning)", n)
	}
}

func TestSessionVerifier_updates_activity(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "active", PasswordHash: "dummy", Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().Add(-30 * time.Minute)
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: created, LastActivity: created,
	}); err != nil {
		t.Fatal(err)
	}

	v := mustSessionVerifier(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameSecure, Value: plaintext})

	gotUser, _, gotErr := v.Verify(ctx, r)
	if gotErr != nil {
		t.Fatalf("Verify error: %v", gotErr)
	}
	if gotUser == nil {
		t.Fatal("Verify returned nil user")
	}

	// Check that LastActivity was updated
	sess, _, _ := db.SessionByHash(ctx, hash)
	if sess.LastActivity.Equal(created) {
		t.Error("LastActivity was not updated after Verify")
	}
	if time.Since(sess.LastActivity) > 5*time.Second {
		t.Errorf("LastActivity not recent: %v", sess.LastActivity)
	}
}

// failingSessionStore injects a configurable backend error from each store
// method so the verifier's fail-closed behavior can be exercised.
type failingSessionStore struct {
	sess    *Session
	user    *User
	sessErr error
	userErr error
}

func (s *failingSessionStore) SessionByHash(context.Context, string) (*Session, bool, error) {
	return s.sess, s.sess != nil, s.sessErr
}

func (s *failingSessionStore) UserByID(context.Context, int64) (*User, bool, error) {
	return s.user, s.user != nil, s.userErr
}

func (s *failingSessionStore) UpdateSessionActivity(context.Context, string, time.Time) error {
	return nil
}

func TestSessionVerifier_Verify_storeError_failsClosed(t *testing.T) {
	t.Parallel()
	// A backend error from the session or user lookup must fail closed: the
	// verifier denies authentication (nil user) and never propagates the error
	// to the caller, so a transient DB fault can neither authenticate a request
	// nor leak through Authenticate.
	now := time.Now()
	liveSession := &Session{TokenHash: "h", UserID: 1, CreatedAt: now, LastActivity: now}
	for _, tc := range []struct {
		name  string
		store *failingSessionStore
	}{
		{"session lookup error", &failingSessionStore{sessErr: context.DeadlineExceeded}},
		{"user lookup error", &failingSessionStore{sess: liveSession, userErr: context.DeadlineExceeded}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := DefaultCookieConfig()
			v := mustSessionVerifier(t, tc.store, WithCookie(cfg))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.AddCookie(&http.Cookie{Name: cfg.EffectiveName(), Value: "token"})
			user, hash, err := v.Verify(t.Context(), r)
			if user != nil || hash != "" || err != nil {
				t.Errorf("Verify() on store error = (%v, %q, %v), want (nil, empty, nil) fail-closed", user, hash, err)
			}
		})
	}
}

// activityErrStore serves a live session and enabled user but fails the
// activity-write, exercising Verify's best-effort activity-update path.
type activityErrStore struct {
	sess *Session
	user *User
}

func (s activityErrStore) SessionByHash(context.Context, string) (*Session, bool, error) {
	return s.sess, s.sess != nil, nil
}

func (s activityErrStore) UserByID(context.Context, int64) (*User, bool, error) {
	return s.user, s.user != nil, nil
}

func (s activityErrStore) UpdateSessionActivity(context.Context, string, time.Time) error {
	return context.DeadlineExceeded
}

func TestSessionVerifier_Verify_activityUpdateError_stillAuthenticates(t *testing.T) {
	t.Parallel()
	// The session-activity write is best-effort: a backend error updating
	// activity must NOT deny an otherwise-valid session. Verify still returns
	// the user and logs exactly one warning.
	now := time.Now()
	store := activityErrStore{
		sess: &Session{TokenHash: "h", UserID: 1, CreatedAt: now, LastActivity: now},
		user: &User{ID: 1, Username: "alice", Role: RoleUser, Enabled: true},
	}
	logger, h := capture.New()
	cfg := DefaultCookieConfig()
	v := mustSessionVerifier(t, store, WithCookie(cfg), WithLogger(logger))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: cfg.EffectiveName(), Value: "token"})

	user, _, err := v.Verify(t.Context(), r)
	if err != nil || user == nil {
		t.Fatalf("Verify() = (%v, %v), want a user and nil error despite the activity-write failure", user, err)
	}
	if n := h.CountMsg("session activity update failed"); n != 1 {
		t.Errorf("Verify() logged %d activity-update warnings, want 1", n)
	}
}
