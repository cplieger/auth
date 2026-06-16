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
		t.Fatalf("HTTPS: expected __Host-sfx_session, got %s", c.Name)
	}
	if !c.Secure {
		t.Fatal("HTTPS: expected Secure=true")
	}
	if got := cfg.CookieName(r); got != "__Host-sfx_session" {
		t.Fatalf("HTTPS: CookieName = %s, want __Host-sfx_session", got)
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
		t.Fatalf("HTTP: expected bare sfx_session, got %s", c.Name)
	}
	if c.Secure {
		t.Fatal("HTTP: expected Secure=false")
	}
	if got := cfg.CookieName(r); got != "sfx_session" {
		t.Fatalf("HTTP: CookieName = %s, want sfx_session", got)
	}
}

func TestCookieConfig_PerRequest_ForwardedProto_RespectsTrust(t *testing.T) {
	t.Parallel()
	// With TrustForwardedHeaders, X-Forwarded-Proto: https drives the HTTPS path.
	trusted := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session", TrustForwardedHeaders: true}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := trusted.CookieName(r); got != "__Host-sfx_session" {
		t.Fatalf("trusted forwarded-proto: CookieName = %s, want __Host-sfx_session", got)
	}

	// Without trust, the forwarded header is ignored -> bare name, no Secure.
	untrusted := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session"}
	if got := untrusted.CookieName(r); got != "sfx_session" {
		t.Fatalf("untrusted forwarded-proto: CookieName = %s, want sfx_session", got)
	}
}

func TestCookieConfig_PerRequest_ReadCookie_RoundTrip(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PosturePerRequest, Name: "sfx_session"}

	// HTTPS writes __Host-sfx_session; reading on an HTTPS request finds it.
	wHTTPS := httptest.NewRecorder()
	rHTTPS := httpsRequest()
	cfg.SetCookie(wHTTPS, rHTTPS, "secure-tok", 3600)
	respHTTPS := wHTTPS.Result()
	defer respHTTPS.Body.Close()
	readReqHTTPS := httpsRequest()
	for _, ck := range respHTTPS.Cookies() {
		readReqHTTPS.AddCookie(ck)
	}
	if got := cfg.ReadCookie(readReqHTTPS); got != "secure-tok" {
		t.Fatalf("HTTPS round-trip: ReadCookie = %q, want secure-tok", got)
	}

	// HTTP writes bare sfx_session; reading on an HTTP request finds it.
	wHTTP := httptest.NewRecorder()
	rHTTP := httptest.NewRequest(http.MethodGet, "/", nil)
	cfg.SetCookie(wHTTP, rHTTP, "lan-tok", 3600)
	respHTTP := wHTTP.Result()
	defer respHTTP.Body.Close()
	readReqHTTP := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, ck := range respHTTP.Cookies() {
		readReqHTTP.AddCookie(ck)
	}
	if got := cfg.ReadCookie(readReqHTTP); got != "lan-tok" {
		t.Fatalf("HTTP round-trip: ReadCookie = %q, want lan-tok", got)
	}
}

// TestCookieConfig_PerRequest_DefaultPostureUnchanged confirms that adding
// PosturePerRequest leaves the default PostureSecure behavior bit-for-bit
// identical: stable __Host- name and Secure=true regardless of request scheme.
func TestCookieConfig_PerRequest_DefaultPostureUnchanged(t *testing.T) {
	t.Parallel()
	cfg := DefaultCookieConfig() // PostureSecure
	httpReq := httptest.NewRequest(http.MethodGet, "/", nil)
	httpsReq := httpsRequest()

	if cfg.CookieName(httpReq) != "__Host-auth_session" {
		t.Fatalf("default over HTTP: name = %s", cfg.CookieName(httpReq))
	}
	if cfg.CookieName(httpsReq) != "__Host-auth_session" {
		t.Fatalf("default over HTTPS: name = %s", cfg.CookieName(httpsReq))
	}

	for _, r := range []*http.Request{httpReq, httpsReq} {
		w := httptest.NewRecorder()
		cfg.SetCookie(w, r, "v", 100)
		resp := w.Result()
		c := resp.Cookies()[0]
		resp.Body.Close()
		if c.Name != "__Host-auth_session" || !c.Secure {
			t.Fatalf("default posture changed: name=%s secure=%v", c.Name, c.Secure)
		}
	}
}
