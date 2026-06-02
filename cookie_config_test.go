package auth

import (
	"crypto/tls"
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
	if cfg.Prefix != "__Host-" {
		t.Fatalf("expected __Host-, got %s", cfg.Prefix)
	}
	if cfg.Path != "/" {
		t.Fatalf("expected /, got %s", cfg.Path)
	}
	if cfg.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected Lax, got %d", cfg.SameSite)
	}
}

func TestCookieConfig_CookieName_HTTPS(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	if got := cfg.CookieName(r); got != "__Host-auth_session" {
		t.Fatalf("expected __Host-auth_session, got %s", got)
	}
}

func TestCookieConfig_CookieName_HTTP(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := cfg.CookieName(r); got != "auth_session" {
		t.Fatalf("expected auth_session, got %s", got)
	}
}

func TestCookieConfig_CustomName(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Name: "my_sess", Prefix: "__Secure-"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	if got := cfg.CookieName(r); got != "__Secure-my_sess" {
		t.Fatalf("expected __Secure-my_sess, got %s", got)
	}
}

func TestCookieConfig_DomainSuppressesHostPrefix(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Name: "sess", Domain: "example.com"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	if got := cfg.CookieName(r); got != "sess" {
		t.Fatalf("expected sess (no prefix), got %s", got)
	}
}

func TestCookieConfig_SetAndRead(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Name: "test_sess", Prefix: CookieNoPrefix}
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
		Name:     "s",
		Prefix:   CookieNoPrefix,
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

func TestCookieConfig_SecureOverride(t *testing.T) {
	t.Parallel()
	secure := true
	cfg := CookieConfig{Name: "s", Prefix: CookieNoPrefix, Secure: &secure}
	r := httptest.NewRequest(http.MethodGet, "/", nil) // HTTP, not HTTPS
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "v", 100)
	resp := w.Result()
	defer resp.Body.Close()
	if !resp.Cookies()[0].Secure {
		t.Fatal("expected Secure=true even on HTTP when overridden")
	}
}

func TestCookieConfig_ClearCookie(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Name: "s", Prefix: CookieNoPrefix}
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
