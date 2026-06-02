package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieConfig_Defaults(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	if cfg.Name != "auth_session" {
		t.Fatalf("expected auth_session, got %s", cfg.Name)
	}
	if cfg.Posture != PostureSecure {
		t.Fatalf("expected PostureSecure, got %d", cfg.Posture)
	}
	if cfg.Path != "/" {
		t.Fatalf("expected /, got %s", cfg.Path)
	}
	if cfg.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected Lax, got %d", cfg.SameSite)
	}
}

func TestCookieConfig_EffectiveName_Secure(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	if got := cfg.EffectiveName(); got != "__Host-auth_session" {
		t.Fatalf("expected __Host-auth_session, got %s", got)
	}
}

func TestCookieConfig_EffectiveName_InsecureLAN(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "auth_session"}
	if got := cfg.EffectiveName(); got != "auth_session" {
		t.Fatalf("expected auth_session, got %s", got)
	}
}

func TestCookieConfig_EffectiveName_ForceSecure(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureForceSecure, Name: "auth_session"}
	if got := cfg.EffectiveName(); got != "__Host-auth_session" {
		t.Fatalf("expected __Host-auth_session, got %s", got)
	}
}

func TestCookieConfig_CustomName(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "my_sess"}
	if got := cfg.EffectiveName(); got != "__Host-my_sess" {
		t.Fatalf("expected __Host-my_sess, got %s", got)
	}
}

func TestCookieConfig_SetAndRead(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "test_sess"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok123", 3600)

	resp := w.Result()
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != "test_sess" {
		t.Fatalf("expected test_sess, got %s", cookies[0].Name)
	}
	if cookies[0].Value != "tok123" {
		t.Fatalf("expected tok123, got %s", cookies[0].Value)
	}

	// Read it back
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])
	if got := cfg.ReadCookie(r2); got != "tok123" {
		t.Fatalf("expected tok123, got %s", got)
	}
}

func TestCookieConfig_CustomSameSiteAndPath(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{
		Posture:  PostureInsecureLAN,
		Name:     "s",
		Path:     "/app",
		SameSite: http.SameSiteStrictMode,
	}
	r := httptest.NewRequest(http.MethodGet, "/app", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "v", 100)
	resp := w.Result()
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.Path != "/app" {
		t.Fatalf("expected /app, got %s", c.Path)
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected Strict, got %d", c.SameSite)
	}
}

func TestCookieConfig_SecurePosture(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "s"}
	r := httptest.NewRequest(http.MethodGet, "/", nil) // HTTP, not HTTPS
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "v", 100)
	resp := w.Result()
	defer resp.Body.Close()
	if !resp.Cookies()[0].Secure {
		t.Fatal("expected Secure=true for PostureSecure regardless of request scheme")
	}
}

func TestCookieConfig_InsecureLAN_NoSecure(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "v", 100)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.Cookies()[0].Secure {
		t.Fatal("expected Secure=false for PostureInsecureLAN")
	}
}

func TestCookieConfig_ClearCookie(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.ClearCookie(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.MaxAge != -1 {
		t.Fatalf("expected MaxAge=-1, got %d", c.MaxAge)
	}
}

func TestCookieConfig_CacheControl(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", 3600)
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", got)
	}
}

func TestCookieConfig_TrustForwardedHeaders_False(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{TrustForwardedHeaders: false}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if cfg.isHTTPS(r) {
		t.Fatal("expected isHTTPS=false when TrustForwardedHeaders=false")
	}
}

func TestCookieConfig_TrustForwardedHeaders_True(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{TrustForwardedHeaders: true}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if !cfg.isHTTPS(r) {
		t.Fatal("expected isHTTPS=true when TrustForwardedHeaders=true and header set")
	}
}

func TestCookieConfig_StableNamePerPosture(t *testing.T) {
	t.Parallel()
	// Verify posture produces ONE stable name regardless of request
	cfg := DefaultCookieConfig()
	r1 := httptest.NewRequest(http.MethodGet, "/", nil) // HTTP
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Forwarded-Proto", "https")
	if cfg.CookieName(r1) != cfg.CookieName(r2) {
		t.Fatal("cookie name should be stable regardless of request")
	}
}
