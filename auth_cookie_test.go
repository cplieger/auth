package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsBrowserRequest_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		accept string
		apiKey string
		want   bool
	}{
		{"browser html", "text/html,application/xhtml+xml", "", true},
		{"browser with wildcard", "text/html, */*", "", true},
		{"api client json", "application/json", "", false},
		{"api key overrides browser", "text/html", "ak_abc123", false},
		{"empty accept", "", "", false},
		{"api key with empty accept", "", "ak_abc123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if tt.apiKey != "" {
				r.Header.Set("X-API-Key", tt.apiKey)
			}
			got := IsBrowserRequest(r)
			if got != tt.want {
				t.Errorf("IsBrowserRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsHTTPS_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		forwardedProto string
		useTLS         bool
		want           bool
	}{
		{"plain http", "", false, false},
		{"tls connection", "", true, true},
		// Default config does NOT trust forwarded headers
		{"forwarded https ignored by default", "https", false, false},
		{"forwarded http", "http", false, false},
		{"tls plus forwarded https", "https", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.useTLS {
				r.TLS = &tls.ConnectionState{}
			}
			if tt.forwardedProto != "" {
				r.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			}
			got := defaultCookieConfig.isHTTPS(r)
			if got != tt.want {
				t.Errorf("isHTTPS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionCookieName_table(t *testing.T) {
	t.Parallel()
	// With deploy-time posture, name is always the same regardless of TLS
	tests := []struct {
		name string
		want string
		tls  bool
	}{
		{"http", CookieNameSecure, false},
		{"https", CookieNameSecure, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := SessionCookieName(r); got != tt.want {
				t.Errorf("SessionCookieName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetSessionCookie_sets_correct_attributes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		token    string
		wantName string
		maxAge   int
		tls      bool
		wantSec  bool
	}{
		// Default posture is PostureSecure: always __Host- + Secure
		{name: "http session", tls: false, token: "tok123", maxAge: 3600, wantName: CookieNameSecure, wantSec: true},
		{name: "https session", tls: true, token: "tok456", maxAge: 7200, wantName: CookieNameSecure, wantSec: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			SetSessionCookie(w, r, tt.token, tt.maxAge)

			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("got %d cookies, want 1", len(cookies))
			}
			c := cookies[0]
			if c.Name != tt.wantName {
				t.Errorf("name = %q, want %q", c.Name, tt.wantName)
			}
			if c.Secure != tt.wantSec {
				t.Errorf("Secure = %v, want %v", c.Secure, tt.wantSec)
			}
			if !c.HttpOnly {
				t.Error("HttpOnly = false")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax", c.SameSite)
			}
		})
	}
}

func TestClearSessionCookie_sets_negative_max_age(t *testing.T) {
	t.Parallel()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ClearSessionCookie(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookies[0].MaxAge)
	}
}

func TestReadSessionCookie_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cookieName string
		value      string
		want       string
		tls        bool
	}{
		// Default posture: always reads __Host-auth_session
		{name: "present", cookieName: CookieNameSecure, value: "mytoken", tls: false, want: "mytoken"},
		{name: "no cookie", cookieName: "", value: "", tls: false, want: ""},
		{name: "wrong name", cookieName: "other", value: "val", tls: false, want: ""},
		{name: "https cookie present", cookieName: CookieNameSecure, value: "sectoken", tls: true, want: "sectoken"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tt.cookieName != "" {
				r.AddCookie(&http.Cookie{Name: tt.cookieName, Value: tt.value})
			}
			if got := ReadSessionCookie(r); got != tt.want {
				t.Errorf("ReadSessionCookie() = %q, want %q", got, tt.want)
			}
		})
	}
}
