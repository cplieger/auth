package auth

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// timeoutSourceCookie is the LAN-posture cookie config shared by the tests in
// this file (same shape as the throttle tests).
var timeoutSourceCookie = CookieConfig{Posture: PostureInsecureLAN, Name: "s"}

// setupAgedSession stores a valid user + session whose CreatedAt/LastActivity
// are age in the past, returning the store and the plaintext token.
func setupAgedSession(t *testing.T, age time.Duration) (*fakeSessionStore, string) {
	t.Helper()
	db := newFakeSessionStore()
	ctx := t.Context()
	user := &User{Username: "u", PasswordHash: "dummy", Role: RoleUser, Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	plaintext, hash := GenerateSessionToken()
	then := time.Now().Add(-age)
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: then, LastActivity: then,
	}); err != nil {
		t.Fatal(err)
	}
	return db, plaintext
}

// TestSessionVerifier_TimeoutSource_ResolvedPerVerify confirms the source is
// consulted on every Verify, so a changed value takes effect immediately: the
// same 30-minute-old session is rejected under a 10-minute source idle and
// accepted once the source grows it to 1h. Rejection happens before the
// activity write, so the first Verify cannot refresh the session and mask the
// second assertion.
func TestSessionVerifier_TimeoutSource_ResolvedPerVerify(t *testing.T) {
	t.Parallel()
	db, plaintext := setupAgedSession(t, 30*time.Minute)

	var idle atomic.Int64
	idle.Store(int64(10 * time.Minute))
	v := mustSessionVerifier(t, db,
		WithCookie(timeoutSourceCookie),
		WithTimeoutSource(func() SessionTimeouts {
			return SessionTimeouts{Idle: time.Duration(idle.Load()), Absolute: 24 * time.Hour}
		}))

	r := throttleRequest(plaintext)
	ctx := t.Context()

	if user, _, err := v.Verify(ctx, r); err != nil || user != nil {
		t.Fatalf("Verify under 10m source idle = (%v, %v), want rejected (nil, nil)", user, err)
	}

	idle.Store(int64(time.Hour))
	if user, _, err := v.Verify(ctx, r); err != nil || user == nil {
		t.Fatalf("Verify under 1h source idle = (%v, %v), want valid session", user, err)
	}
}

// TestSessionVerifier_TimeoutSource_NonPositiveFallsBackToStatic confirms
// per-resolution validation: a source returning non-positive values must not
// produce always-expired sessions; the static configured values apply instead.
func TestSessionVerifier_TimeoutSource_NonPositiveFallsBackToStatic(t *testing.T) {
	t.Parallel()
	db, plaintext := setupAgedSession(t, 30*time.Minute)

	v := mustSessionVerifier(t, db,
		WithCookie(timeoutSourceCookie),
		WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour),
		WithTimeoutSource(func() SessionTimeouts { return SessionTimeouts{Idle: 0, Absolute: -time.Hour} }))

	user, _, err := v.Verify(t.Context(), throttleRequest(plaintext))
	if err != nil || user == nil {
		t.Fatalf("Verify with non-positive source = (%v, %v), want valid via static fallback", user, err)
	}
}

// TestAuthenticator_TimeoutSource_ThreadsToDefaultChain confirms
// New passes the source through to the default session verifier:
// a 30-minute-old session fails authentication once the source's idle is 10
// minutes, even though the static default (1h) would accept it.
func TestAuthenticator_TimeoutSource_ThreadsToDefaultChain(t *testing.T) {
	t.Parallel()
	db, plaintext := setupAgedSession(t, 30*time.Minute)

	a := mustAuthenticator(t, db,
		WithCookie(timeoutSourceCookie),
		WithTimeoutSource(func() SessionTimeouts {
			return SessionTimeouts{Idle: 10 * time.Minute, Absolute: 24 * time.Hour}
		}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: plaintext})
	if _, _, err := a.Authenticate(r); err == nil {
		t.Fatal("Authenticate = nil error, want ErrUnauthenticated under shrunk source idle")
	}
}

// TestSessionVerifier_TimeoutSource_ClampsThrottleToHalfIdle confirms the
// per-resolution clamp: with a configured throttle above half the resolved
// idle timeout, activity writes recur at idle/2, keeping LastActivity fresh
// enough that an active session can never idle-expire from throttling alone.
func TestSessionVerifier_TimeoutSource_ClampsThrottleToHalfIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cs, plaintext, hash := setupThrottleSession(t)
		// Static idle 1h passes construction validation (throttle 80ms < 1h).
		// At runtime the source resolves a 100ms idle, clamping the effective
		// throttle to idle/2 = 50ms.
		v := mustSessionVerifier(t, cs,
			WithCookie(timeoutSourceCookie),
			WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour),
			WithActivityThrottle(80*time.Millisecond),
			WithTimeoutSource(func() SessionTimeouts {
				return SessionTimeouts{Idle: 100 * time.Millisecond, Absolute: 24 * time.Hour}
			}))
		ctx := t.Context()
		r := throttleRequest(plaintext)

		if _, _, err := v.Verify(ctx, r); err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if got := cs.count(hash); got != 1 {
			t.Fatalf("initial writes = %d, want 1", got)
		}

		// 60ms sits past the 50ms clamp but inside the raw 80ms window, so a
		// second write here is only possible if the clamp took effect. The
		// session stays valid: write 1 refreshed LastActivity, and 60ms is
		// within the 100ms resolved idle.
		synctest.Sleep(60 * time.Millisecond) // virtual time inside the bubble
		if _, _, err := v.Verify(ctx, r); err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if got := cs.count(hash); got != 2 {
			t.Fatalf("writes after 60ms = %d, want 2 (clamped window 50ms elapsed)", got)
		}
	})
}
