package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// stubVerifier is a CredentialVerifier that returns a fixed result and records
// how many times it was invoked.
type stubVerifier struct {
	user   *User
	called *int32
	hash   string
}

func (s *stubVerifier) Verify(_ context.Context, _ *http.Request) (*User, string, error) {
	atomic.AddInt32(s.called, 1)
	return s.user, s.hash, nil
}

// TestAuthenticator_WithVerifiers_ResolvesThroughInjected confirms that an
// injected verifier chain is used and a request resolves through it.
func TestAuthenticator_WithVerifiers_ResolvesThroughInjected(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	want := &User{ID: 42, Username: "custom", Role: RoleUser, Enabled: true}
	var called int32

	a := NewAuthenticator(db, WithVerifiers([]CredentialVerifier{
		&stubVerifier{user: want, hash: "custom-hash", called: &called},
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	got, hash, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if got != want {
		t.Fatalf("resolved user = %+v, want %+v", got, want)
	}
	if hash != "custom-hash" {
		t.Fatalf("hash = %q, want custom-hash", hash)
	}
	if n := atomic.LoadInt32(&called); n != 1 {
		t.Fatalf("injected verifier called %d times, want 1", n)
	}
}

// TestAuthenticator_WithVerifiers_EmptyFallsBackToDefault confirms that an
// empty injected chain falls back to the default session + API-key chain so
// existing behavior is preserved.
func TestAuthenticator_WithVerifiers_EmptyFallsBackToDefault(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := context.Background()

	user := &User{Username: "alice", PasswordHash: "dummy", Role: RoleUser, Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	a := NewAuthenticator(db,
		WithCookie(cfg),
		WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour),
		WithVerifiers(nil), // empty -> default chain
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: plaintext})
	got, _, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate via default chain error: %v", err)
	}
	if got == nil || got.Username != "alice" {
		t.Fatalf("default chain did not resolve session, got %+v", got)
	}
}
