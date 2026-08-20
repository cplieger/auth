package auth

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- Cookie Posture Tests ---

func TestPosture_SecureNeverEmitsUnprefixedName(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "sess"}
	// Regardless of request scheme, name is always prefixed
	for i := range 100 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if i%2 == 0 {
			r.Header.Set("X-Forwarded-Proto", "http")
		}
		name := cfg.CookieName(r)
		if name != "__Host-sess" {
			t.Fatalf("PostureSecure emitted unprefixed name: %q", name)
		}
	}
}

func TestPosture_InsecureLANNeverEmitsHostPrefix(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "sess"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	name := cfg.CookieName(r)
	if name != "sess" {
		t.Fatalf("PostureInsecureLAN emitted prefixed name: %q", name)
	}
}

func TestPosture_ForceSecure_CookieAttributes(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureForceSecure, Name: "sess"}
	r := httptest.NewRequest(http.MethodGet, "/", nil) // no TLS
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", 3600)
	c := w.Result().Cookies()[0]
	if !c.Secure {
		t.Errorf("PostureForceSecure cookie Secure = %v, want true regardless of request scheme", c.Secure)
	}
	if c.Name != "__Host-sess" {
		t.Errorf("PostureForceSecure cookie name = %q, want %q", c.Name, "__Host-sess")
	}
}

// --- CSRF Nonce Uniqueness Tests ---

func TestCSRFToken_NonceUniqueness(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sessHash := "same-session"
	tokens := make(map[string]struct{}, 1000)
	for range 1000 {
		tok, err := CSRFToken(key, sessHash)
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := tokens[tok]; dup {
			t.Fatal("CSRF tokens should be unique due to nonce; got duplicate")
		}
		tokens[tok] = struct{}{}
	}
}

func TestCSRFToken_SessionBinding(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	tok, err := CSRFToken(key, "sessionA")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("rejects a different session", func(t *testing.T) {
		if err := VerifyCSRFToken(key, "sessionB", tok, time.Hour); err != ErrTokenInvalid {
			t.Errorf("VerifyCSRFToken(other session) = %v, want ErrTokenInvalid", err)
		}
	})
	t.Run("accepts the issuing session", func(t *testing.T) {
		if err := VerifyCSRFToken(key, "sessionA", tok, time.Hour); err != nil {
			t.Errorf("VerifyCSRFToken(same session) = %v, want nil", err)
		}
	})
}

// --- TrustForwardedHeaders Tests ---

func TestTrustForwardedHeaders_Disabled_IgnoresHeader(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{TrustForwardedHeaders: false}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if cfg.isHTTPS(r) {
		t.Fatal("isHTTPS should be false when TrustForwardedHeaders=false")
	}
}

func TestTrustForwardedHeaders_Enabled_HonorsHeader(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{TrustForwardedHeaders: true}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if !cfg.isHTTPS(r) {
		t.Fatal("isHTTPS should be true when TrustForwardedHeaders=true and header set")
	}
}

func TestTrustForwardedHeaders_Enabled_FalseForHTTP(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{TrustForwardedHeaders: true}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "http")
	if cfg.isHTTPS(r) {
		t.Fatal("isHTTPS should be false when forwarded proto is http")
	}
}

// --- Session Rotation Tests ---

func TestRotateSessionToken_ProducesNewToken(t *testing.T) {
	t.Parallel()
	oldPlain, oldHash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	newPlain, newHash, gotOldHash, err := RotateSessionToken(oldPlain)
	if err != nil {
		t.Fatal(err)
	}
	if gotOldHash != oldHash {
		t.Errorf("RotateSessionToken() oldHash = %q, want %q", gotOldHash, oldHash)
	}
	if newPlain == oldPlain {
		t.Error("RotateSessionToken() new plaintext equals the old one, want a fresh token")
	}
	if newHash == oldHash {
		t.Error("RotateSessionToken() new hash equals the old one, want a fresh hash")
	}
	if got := SessionHash(newPlain); got != newHash {
		t.Errorf("SessionHash(new plaintext) = %q, want the returned new hash %q", got, newHash)
	}
}

func TestRotateSessionToken_OldTokenBecomesInvalid(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	db := newFakeSessionStore()

	user := &User{Username: "rotate-user", PasswordHash: "x", Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	oldPlain, oldHash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: oldHash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Rotate
	_, newHash, _, err := RotateSessionToken(oldPlain)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate store rotation: delete old, create new
	if err := db.DeleteSession(ctx, oldHash); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(ctx, &Session{
		TokenHash: newHash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Old token should no longer resolve
	if sess, _, _ := db.SessionByHash(ctx, oldHash); sess != nil {
		t.Error("old session still resolves after rotation, want deleted")
	}
	// New token should resolve
	if sess, _, _ := db.SessionByHash(ctx, newHash); sess == nil {
		t.Error("new session does not resolve after rotation, want present")
	}
}

// --- Role Interface Tests ---

func TestRoleInterface_SessionReader(t *testing.T) {
	t.Parallel()
	var _ SessionReader = newFakeSessionStore()
}

func TestRoleInterface_SessionWriter(t *testing.T) {
	t.Parallel()
	var _ SessionWriter = newFakeSessionStore()
}

func TestRoleInterface_SessionStore(t *testing.T) {
	t.Parallel()
	var _ SessionStore = newFakeSessionStore()
}

func TestRoleInterface_UserReader(t *testing.T) {
	t.Parallel()
	var _ UserReader = newFakeSessionStore()
}

func TestRoleInterface_APIKeyReader(t *testing.T) {
	t.Parallel()
	var _ APIKeyReader = newFakeSessionStore()
}

func TestRoleInterface_AuthenticatorStore(t *testing.T) {
	t.Parallel()
	var _ AuthenticatorStore = newFakeSessionStore()
}

func TestRoleInterface_SessionVerifierStore(t *testing.T) {
	t.Parallel()
	var _ SessionVerifierStore = newFakeSessionStore()
}

func TestRoleInterface_APIKeyVerifierStore(t *testing.T) {
	t.Parallel()
	var _ APIKeyVerifierStore = newFakeSessionStore()
}
