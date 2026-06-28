package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// countingStore wraps fakeSessionStore and counts UpdateSessionActivity calls
// per session hash. It satisfies SessionVerifierStore via embedding.
type countingStore struct {
	*fakeSessionStore
	counts map[string]int
	mu     sync.Mutex
}

func newCountingStore() *countingStore {
	return &countingStore{
		fakeSessionStore: newFakeSessionStore(),
		counts:           make(map[string]int),
	}
}

func (c *countingStore) UpdateSessionActivity(ctx context.Context, tokenHash string, now time.Time) error {
	c.mu.Lock()
	c.counts[tokenHash]++
	c.mu.Unlock()
	return c.fakeSessionStore.UpdateSessionActivity(ctx, tokenHash, now)
}

func (c *countingStore) count(tokenHash string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[tokenHash]
}

// setupThrottleSession creates a valid session in the store and returns the
// store, the plaintext token, and its hash.
func setupThrottleSession(t *testing.T) (*countingStore, string, string) {
	t.Helper()
	cs := newCountingStore()
	ctx := context.Background()
	user := &User{Username: "u", PasswordHash: "dummy", Role: RoleUser, Enabled: true}
	if err := cs.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := cs.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}
	return cs, plaintext, hash
}

func throttleRequest(plaintext string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: plaintext})
	return r
}

// TestSessionVerifier_Throttle_Zero_WritesEveryRequest confirms the default
// (throttle 0) preserves write-on-every-request behavior.
func TestSessionVerifier_Throttle_Zero_WritesEveryRequest(t *testing.T) {
	t.Parallel()
	cs, plaintext, hash := setupThrottleSession(t)
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	v := mustSessionVerifier(t, cs, WithCookie(cfg), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	ctx := context.Background()
	r := throttleRequest(plaintext)

	const n = 5
	for range n {
		if _, _, err := v.Verify(ctx, r); err != nil {
			t.Fatalf("Verify error: %v", err)
		}
	}
	if got := cs.count(hash); got != n {
		t.Fatalf("throttle=0: writes = %d, want %d (every request)", got, n)
	}
}

// TestSessionVerifier_Throttle_Positive_AtMostOncePerWindow confirms that with
// d>0, repeated requests within the window produce at most one write per hash.
func TestSessionVerifier_Throttle_Positive_AtMostOncePerWindow(t *testing.T) {
	t.Parallel()
	cs, plaintext, hash := setupThrottleSession(t)
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	v := mustSessionVerifier(t, cs, WithCookie(cfg), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour),
		WithActivityThrottle(30*time.Minute))
	ctx := context.Background()
	r := throttleRequest(plaintext)

	for range 5 {
		if _, _, err := v.Verify(ctx, r); err != nil {
			t.Fatalf("Verify error: %v", err)
		}
	}
	if got := cs.count(hash); got != 1 {
		t.Fatalf("throttle=30m: writes = %d, want 1 within window", got)
	}
}

// TestSessionVerifier_Throttle_WritesAgainAfterWindow confirms a second write
// occurs once the throttle window has elapsed.
func TestSessionVerifier_Throttle_WritesAgainAfterWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cs, plaintext, hash := setupThrottleSession(t)
		cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
		v := mustSessionVerifier(t, cs, WithCookie(cfg), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour),
			WithActivityThrottle(10*time.Millisecond))
		ctx := context.Background()
		r := throttleRequest(plaintext)

		if _, _, err := v.Verify(ctx, r); err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if _, _, err := v.Verify(ctx, r); err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if got := cs.count(hash); got != 1 {
			t.Fatalf("within window: writes = %d, want 1", got)
		}

		time.Sleep(30 * time.Millisecond) // virtual time: advances instantly inside the bubble
		if _, _, err := v.Verify(ctx, r); err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if got := cs.count(hash); got != 2 {
			t.Fatalf("after window elapsed: writes = %d, want 2", got)
		}
	})
}

// TestSessionVerifier_Throttle_ConcurrentSafe confirms the throttle map is
// concurrency-safe and collapses concurrent in-window requests to one write.
// Run under -race to detect data races.
func TestSessionVerifier_Throttle_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	cs, plaintext, hash := setupThrottleSession(t)
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	v := mustSessionVerifier(t, cs, WithCookie(cfg), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour),
		WithActivityThrottle(30*time.Minute))
	ctx := context.Background()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			r := throttleRequest(plaintext)
			if _, _, err := v.Verify(ctx, r); err != nil {
				t.Errorf("Verify error: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := cs.count(hash); got != 1 {
		t.Fatalf("concurrent in-window: writes = %d, want 1", got)
	}
}
