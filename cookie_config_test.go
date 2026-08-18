package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieConfig_Defaults(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig()
	if cfg.Name != "auth_session" {
		t.Errorf("default Name = %q, want %q", cfg.Name, "auth_session")
	}
	if cfg.Posture != PostureSecure {
		t.Errorf("default Posture = %d, want PostureSecure", cfg.Posture)
	}
	if cfg.Path != "/" {
		t.Errorf("default Path = %q, want %q", cfg.Path, "/")
	}
	if cfg.SameSite != http.SameSiteLaxMode {
		t.Errorf("default SameSite = %d, want Lax", cfg.SameSite)
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
		t.Errorf("cookie name = %q, want %q", cookies[0].Name, "test_sess")
	}
	if cookies[0].Value != "tok123" {
		t.Errorf("cookie value = %q, want %q", cookies[0].Value, "tok123")
	}

	// Read it back
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])
	if got := cfg.ReadCookie(r2); got != "tok123" {
		t.Errorf("ReadCookie() = %q, want %q", got, "tok123")
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
		t.Errorf("cookie Path = %q, want %q", c.Path, "/app")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %d, want Strict", c.SameSite)
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

// TestCookieConfig_Secure_ReadCookie_ignoresUnprefixedCookie pins the
// session-fixation defense: under a __Host- posture, a bare (unprefixed) cookie
// an attacker can set over plain HTTP must not be read as the session token.
func TestCookieConfig_Secure_ReadCookie_ignoresUnprefixedCookie(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "sess"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sess", Value: "attacker-token"})
	if got := cfg.ReadCookie(r); got != "" {
		t.Fatalf("ReadCookie read an unprefixed cookie %q under PostureSecure, want \"\" (session fixation)", got)
	}
}

// TestCookieConfig_isHTTPS_trustedRequiresExactHTTPS confirms that, even when
// X-Forwarded-Proto is trusted, only the exact lowercase value "https" is
// treated as HTTPS. Case variants, surrounding whitespace, and comma lists must
// not be accepted, so a proxy misconfiguration cannot silently flip the scheme.
func TestCookieConfig_isHTTPS_trustedRequiresExactHTTPS(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{TrustForwardedHeaders: true}
	cases := []struct {
		value string
		want  bool
	}{
		{"https", true},
		{"HTTPS", false},
		{"Https", false},
		{"https ", false},
		{" https", false},
		{"https,http", false},
		{"https, http", false},
		{"http", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.value != "" {
				r.Header.Set("X-Forwarded-Proto", tc.value)
			}
			if got := cfg.isHTTPS(r); got != tc.want {
				t.Errorf("isHTTPS(X-Forwarded-Proto=%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// TestCookieConfig_SetCookie_alwaysHttpOnly confirms the session cookie is
// HttpOnly under every posture, including the insecure-LAN posture that drops
// the Secure flag.
func TestCookieConfig_SetCookie_alwaysHttpOnly(t *testing.T) {
	t.Parallel()
	for _, posture := range []CookiePosture{PostureSecure, PostureInsecureLAN, PostureForceSecure, PosturePerRequest} {
		t.Run(fmt.Sprintf("posture_%d", posture), func(t *testing.T) {
			t.Parallel()
			cfg := CookieConfig{Posture: posture, Name: "s"}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			cfg.SetCookie(w, r, "tok", 3600)
			resp := w.Result()
			defer resp.Body.Close()
			if c := resp.Cookies()[0]; !c.HttpOnly {
				t.Errorf("posture %d: cookie HttpOnly = false, want true", posture)
			}
		})
	}
}

func TestCookiePosture_String(t *testing.T) {
	t.Parallel()
	cases := []struct {
		posture CookiePosture
		want    string
	}{
		{PostureSecure, "PostureSecure"},
		{PostureInsecureLAN, "PostureInsecureLAN"},
		{PostureForceSecure, "PostureForceSecure"},
		{PosturePerRequest, "PosturePerRequest"},
		{CookiePosture(99), "CookiePosture(99)"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			if got := tc.posture.String(); got != tc.want {
				t.Errorf("CookiePosture(%d).String() = %q, want %q", int(tc.posture), got, tc.want)
			}
		})
	}
}
