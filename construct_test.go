package auth

import (
	"testing"
	"time"
)

// mustSessionVerifier builds a SessionVerifier and fails the test if the
// configuration is rejected. Use it for the common case of a valid config;
// tests that exercise a rejected config call NewSessionVerifier directly and
// assert on the error. It takes testing.TB so benchmarks can use it too.
func mustSessionVerifier(tb testing.TB, store SessionVerifierStore, opts ...Option) *SessionVerifier {
	tb.Helper()
	v, err := NewSessionVerifier(store, opts...)
	if err != nil {
		tb.Fatalf("NewSessionVerifier: %v", err)
	}
	return v
}

// mustAuthenticator builds an Authenticator and fails the test if the
// configuration is rejected. See [mustSessionVerifier].
func mustAuthenticator(tb testing.TB, store AuthStore, opts ...Option) *Authenticator {
	tb.Helper()
	a, err := New(store, opts...)
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return a
}

func TestNewSessionVerifier_rejects_invalid_cookie_config(t *testing.T) {
	t.Parallel()
	// The default (__Host-) posture with a non-root Path produces a cookie
	// browsers reject; construction must fail fast rather than warn.
	if _, err := NewSessionVerifier(newFakeSessionStore(), WithCookie(CookieConfig{Path: "/app"})); err == nil {
		t.Fatal("NewSessionVerifier(__Host- posture + non-root Path) error = nil, want non-nil")
	}
}

func TestNewSessionVerifier_rejects_throttle_not_less_than_idle(t *testing.T) {
	t.Parallel()
	if _, err := NewSessionVerifier(newFakeSessionStore(),
		WithIdleTimeout(time.Hour), WithActivityThrottle(time.Hour)); err == nil {
		t.Fatal("NewSessionVerifier(throttle == idle) error = nil, want non-nil")
	}
}

func TestNewSessionVerifier_rejects_negative_idle_timeout(t *testing.T) {
	t.Parallel()
	// defaults() substitutes the package default only for a zero timeout, so a
	// negative one would survive to request time and expire every session
	// immediately. Construction must reject it.
	if _, err := NewSessionVerifier(newFakeSessionStore(), WithIdleTimeout(-time.Hour)); err == nil {
		t.Fatal("NewSessionVerifier(negative idle timeout) error = nil, want non-nil")
	}
}

func TestNewSessionVerifier_rejects_negative_abs_timeout(t *testing.T) {
	t.Parallel()
	if _, err := NewSessionVerifier(newFakeSessionStore(), WithAbsTimeout(-time.Hour)); err == nil {
		t.Fatal("NewSessionVerifier(negative absolute timeout) error = nil, want non-nil")
	}
}

func TestNew_rejects_invalid_cookie_config(t *testing.T) {
	t.Parallel()
	// A __Host- posture with a Domain is rejected by browsers; fail fast.
	if _, err := New(newFakeSessionStore(), WithCookie(CookieConfig{Domain: "example.com"})); err == nil {
		t.Fatal("New(__Host- posture + Domain) error = nil, want non-nil")
	}
}

func TestNew_accepts_default_config(t *testing.T) {
	t.Parallel()
	if _, err := New(newFakeSessionStore()); err != nil {
		t.Fatalf("New(defaults) error = %v, want nil", err)
	}
}

func TestNew_rejects_negative_idle_timeout(t *testing.T) {
	t.Parallel()
	// Confirms the positivity check is enforced through the Authenticator
	// constructor too, not just NewSessionVerifier.
	if _, err := New(newFakeSessionStore(), WithIdleTimeout(-time.Second)); err == nil {
		t.Fatal("New(negative idle timeout) error = nil, want non-nil")
	}
}
