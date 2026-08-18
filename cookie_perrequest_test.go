package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// httpsRequest returns a request that isHTTPS() reports as HTTPS via r.TLS.
func httpsRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	return r
}

func TestCookieConfig_PerRequest_HTTPS_EmitsHostSecure(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session"}
	r := httpsRequest()
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", 3600)

	resp := w.Result()
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.Name != "__Host-sfx_session" {
		t.Errorf("HTTPS cookie name = %q, want %q", c.Name, "__Host-sfx_session")
	}
	if !c.Secure {
		t.Errorf("HTTPS cookie Secure = %v, want true", c.Secure)
	}
	if got := cfg.CookieName(r); got != "__Host-sfx_session" {
		t.Errorf("HTTPS CookieName() = %q, want %q", got, "__Host-sfx_session")
	}
}

func TestCookieConfig_PerRequest_HTTP_EmitsBareNoSecure(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session"}
	r := httptest.NewRequest(http.MethodGet, "/", nil) // plain HTTP, no TLS
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "tok", 3600)

	resp := w.Result()
	defer resp.Body.Close()
	c := resp.Cookies()[0]
	if c.Name != "sfx_session" {
		t.Errorf("HTTP cookie name = %q, want bare %q", c.Name, "sfx_session")
	}
	if c.Secure {
		t.Errorf("HTTP cookie Secure = %v, want false", c.Secure)
	}
	if got := cfg.CookieName(r); got != "sfx_session" {
		t.Errorf("HTTP CookieName() = %q, want %q", got, "sfx_session")
	}
}

func TestCookieConfig_PerRequest_ForwardedProto_RespectsTrust(t *testing.T) {
	t.Parallel()
	t.Run("trusted header drives the HTTPS name", func(t *testing.T) {
		t.Parallel()
		trusted := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session", TrustForwardedHeaders: true}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		if got := trusted.CookieName(r); got != "__Host-sfx_session" {
			t.Errorf("trusted forwarded-proto CookieName() = %q, want %q", got, "__Host-sfx_session")
		}
	})
	t.Run("untrusted header is ignored", func(t *testing.T) {
		t.Parallel()
		untrusted := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Forwarded-Proto", "https")
		if got := untrusted.CookieName(r); got != "sfx_session" {
			t.Errorf("untrusted forwarded-proto CookieName() = %q, want bare %q", got, "sfx_session")
		}
	})
}

func TestCookieConfig_PerRequest_ReadCookie_RoundTrip(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session"}

	t.Run("https writes and reads the __Host- name", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		cfg.SetCookie(w, httpsRequest(), "secure-tok", 3600)
		resp := w.Result()
		defer resp.Body.Close()
		readReq := httpsRequest()
		for _, ck := range resp.Cookies() {
			readReq.AddCookie(ck)
		}
		if got := cfg.ReadCookie(readReq); got != "secure-tok" {
			t.Errorf("HTTPS round-trip ReadCookie() = %q, want %q", got, "secure-tok")
		}
	})
	t.Run("http writes and reads the bare name", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		cfg.SetCookie(w, httptest.NewRequest(http.MethodGet, "/", nil), "lan-tok", 3600)
		resp := w.Result()
		defer resp.Body.Close()
		readReq := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, ck := range resp.Cookies() {
			readReq.AddCookie(ck)
		}
		if got := cfg.ReadCookie(readReq); got != "lan-tok" {
			t.Errorf("HTTP round-trip ReadCookie() = %q, want %q", got, "lan-tok")
		}
	})
}

// TestCookieConfig_PerRequest_DefaultPostureUnchanged confirms that adding
// PosturePerRequest leaves the default PostureSecure behavior bit-for-bit
// identical: stable __Host- name and Secure=true regardless of request scheme.
func TestCookieConfig_PerRequest_DefaultPostureUnchanged(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig() // PostureSecure
	httpReq := httptest.NewRequest(http.MethodGet, "/", nil)
	httpsReq := httpsRequest()

	if got := cfg.CookieName(httpReq); got != "__Host-auth_session" {
		t.Errorf("default posture CookieName(HTTP) = %q, want %q", got, "__Host-auth_session")
	}
	if got := cfg.CookieName(httpsReq); got != "__Host-auth_session" {
		t.Errorf("default posture CookieName(HTTPS) = %q, want %q", got, "__Host-auth_session")
	}

	for _, r := range []*http.Request{httpReq, httpsReq} {
		w := httptest.NewRecorder()
		cfg.SetCookie(w, r, "v", 100)
		resp := w.Result()
		c := resp.Cookies()[0]
		resp.Body.Close()
		if c.Name != "__Host-auth_session" || !c.Secure {
			t.Errorf("default posture SetCookie emitted name=%q secure=%v, want __Host-auth_session with Secure", c.Name, c.Secure)
		}
	}
}
