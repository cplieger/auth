package auth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNew_NoOptions_AppliesDefaults verifies that constructing an
// Authenticator with NO options applies the same defaults as the old struct-field
// config: IdleTimeout=1h, AbsTimeout=24h, LoginPath="/login", Logger=slog.Default.
func TestNew_NoOptions_AppliesDefaults(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore())
	if a.cfg.idleTimeout != DefaultIdleTimeout {
		t.Errorf("idleTimeout = %v, want %v", a.cfg.idleTimeout, DefaultIdleTimeout)
	}
	if a.cfg.absTimeout != DefaultAbsTimeout {
		t.Errorf("absTimeout = %v, want %v", a.cfg.absTimeout, DefaultAbsTimeout)
	}
	if a.loginPath() != "/login" {
		t.Errorf("loginPath = %q, want /login", a.loginPath())
	}
}

// TestNewSessionVerifier_NoOptions_AppliesDefaults verifies the SessionVerifier
// uses default timeouts when no options are provided.
func TestNewSessionVerifier_NoOptions_AppliesDefaults(t *testing.T) {
	t.Parallel()
	v := mustSessionVerifier(t, newFakeSessionStore())
	if v.cfg.idleTimeout != DefaultIdleTimeout {
		t.Errorf("idleTimeout = %v, want %v", v.cfg.idleTimeout, DefaultIdleTimeout)
	}
	if v.cfg.absTimeout != DefaultAbsTimeout {
		t.Errorf("absTimeout = %v, want %v", v.cfg.absTimeout, DefaultAbsTimeout)
	}
	// Logger should fall back to slog.Default()
	if v.logger() != slog.Default() {
		t.Error("logger() should return slog.Default() when no WithLogger is set")
	}
}

// TestNewSessionVerifier_NoOptions_SessionValid verifies a session created 5 minutes
// ago is still valid with default timeouts (the zero-timeout regression).
func TestNewSessionVerifier_NoOptions_SessionValid(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "default_user", PasswordHash: "dummy", Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash := GenerateSessionToken()
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now.Add(-5 * time.Minute), LastActivity: now.Add(-5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	// Use NO timeout options — defaults must keep 5-minute-old session valid
	v := mustSessionVerifier(t, db)
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: plaintext})

	gotUser, _, gotErr := v.Verify(ctx, r)
	if gotErr != nil {
		t.Fatalf("Verify error: %v", gotErr)
	}
	if gotUser == nil {
		t.Fatal("expected user, got nil (zero-timeout regression)")
	}
	if gotUser.ID != user.ID {
		t.Errorf("user ID = %d, want %d", gotUser.ID, user.ID)
	}
}

// TestNew_NoOptions_SessionValid verifies the full Authenticator
// flow without explicit timeout options.
func TestNew_NoOptions_SessionValid(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "noopt_user", PasswordHash: "dummy", Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash := GenerateSessionToken()
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now.Add(-30 * time.Minute), LastActivity: now.Add(-10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db) // NO options
	r, _ := http.NewRequest(http.MethodGet, "/api/data", nil)
	r.AddCookie(&http.Cookie{Name: defaultSecureCookieName, Value: plaintext})

	gotUser, gotHash, gotErr := a.Authenticate(r)
	if gotErr != nil {
		t.Fatalf("Authenticate error: %v", gotErr)
	}
	if gotUser.ID != user.ID {
		t.Errorf("user ID = %d, want %d", gotUser.ID, user.ID)
	}
	if gotHash != hash {
		t.Errorf("hash = %q, want %q", gotHash, hash)
	}
}

// TestNewAPIKeyVerifier_NoOptions verifies that NewAPIKeyVerifier works with
// an empty option slice.
func TestNewAPIKeyVerifier_NoOptions(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "apinoopt", PasswordHash: "dummy", Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix := GenerateAPIKey("ak_")
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	v := NewAPIKeyVerifier(db) // no options
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Api-Key", plaintext)

	gotUser, _, gotErr := v.Verify(ctx, r)
	if gotErr != nil {
		t.Fatalf("Verify error: %v", gotErr)
	}
	if gotUser == nil || gotUser.ID != user.ID {
		t.Fatalf("user mismatch: got %v", gotUser)
	}
}

// TestWithX_OptionOrderDoesNotMatter verifies that option order is irrelevant.
func TestWithX_OptionOrderDoesNotMatter(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cookie := CookieConfig{Posture: PostureInsecureLAN, Name: "custom_sess"}

	// Order A: logger, idle, abs, cookie, loginPath
	a1 := mustAuthenticator(t, newFakeSessionStore(),
		WithLogger(logger),
		WithIdleTimeout(2*time.Hour),
		WithAbsTimeout(48*time.Hour),
		WithCookie(cookie),
		WithLoginPath("/signin"),
	)
	// Order B: reverse
	a2 := mustAuthenticator(t, newFakeSessionStore(),
		WithLoginPath("/signin"),
		WithCookie(cookie),
		WithAbsTimeout(48*time.Hour),
		WithIdleTimeout(2*time.Hour),
		WithLogger(logger),
	)

	if a1.cfg.idleTimeout != a2.cfg.idleTimeout {
		t.Error("idleTimeout differs with option order")
	}
	if a1.cfg.absTimeout != a2.cfg.absTimeout {
		t.Error("absTimeout differs with option order")
	}
	if a1.cfg.loginPath != a2.cfg.loginPath {
		t.Error("loginPath differs with option order")
	}
	if a1.cfg.logger != a2.cfg.logger {
		t.Error("logger differs with option order")
	}
	if a1.cfg.cookie.Name != a2.cfg.cookie.Name {
		t.Error("cookie.Name differs with option order")
	}
}

// TestWithX_IndependentThreading verifies each option only modifies its own field.
func TestWithX_IndependentThreading(t *testing.T) {
	t.Parallel()
	base := mustAuthenticator(t, newFakeSessionStore())

	withIdle := mustAuthenticator(t, newFakeSessionStore(), WithIdleTimeout(5*time.Hour))
	if withIdle.cfg.absTimeout != DefaultAbsTimeout {
		t.Errorf("WithIdleTimeout affected absTimeout: %v", withIdle.cfg.absTimeout)
	}
	if withIdle.cfg.loginPath != base.cfg.loginPath {
		t.Error("WithIdleTimeout affected loginPath")
	}

	withAbs := mustAuthenticator(t, newFakeSessionStore(), WithAbsTimeout(72*time.Hour))
	if withAbs.cfg.idleTimeout != DefaultIdleTimeout {
		t.Errorf("WithAbsTimeout affected idleTimeout: %v", withAbs.cfg.idleTimeout)
	}

	withLogin := mustAuthenticator(t, newFakeSessionStore(), WithLoginPath("/auth"))
	if withLogin.cfg.idleTimeout != DefaultIdleTimeout {
		t.Errorf("WithLoginPath affected idleTimeout: %v", withLogin.cfg.idleTimeout)
	}
	if withLogin.cfg.absTimeout != DefaultAbsTimeout {
		t.Errorf("WithLoginPath affected absTimeout: %v", withLogin.cfg.absTimeout)
	}
}

// TestNewHasher_NoPepper_EqualsOldBehavior verifies that NewHasher with no
// WithPepper option produces hashes verifiable by package-level VerifyPassword.
func TestNewHasher_NoPepper_EqualsOldBehavior(t *testing.T) {
	t.Parallel()
	h, err := NewHasher(DefaultArgon2Params()) // no WithPepper
	if err != nil {
		t.Fatal(err)
	}
	hash := h.Hash("test-password")
	// Package-level verify (no pepper) should work
	ok, err := VerifyPassword("test-password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("Hasher with no pepper produced hash not verifiable by VerifyPassword")
	}
}

// TestNew_NilOptionSlice verifies passing an explicit nil slice works.
func TestNew_NilOptionSlice(t *testing.T) {
	t.Parallel()
	var opts []Option
	a := mustAuthenticator(t, newFakeSessionStore(), opts...)
	if a.cfg.idleTimeout != DefaultIdleTimeout {
		t.Errorf("nil slice: idleTimeout = %v, want %v", a.cfg.idleTimeout, DefaultIdleTimeout)
	}
}

// TestRequireAuth_DefaultLoginPath_NoOptions verifies the login redirect uses
// "/login" when no WithLoginPath is set.
func TestRequireAuth_DefaultLoginPath_NoOptions(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore()) // NO options
	r, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	_, _, ok := a.RequireAuth(w, r)
	if ok {
		t.Fatal("expected ok=false")
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Errorf("Location = %q, want prefix /login", loc)
	}
}
