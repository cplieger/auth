package auth

import (
	"net/http"
	"strings"
)

// Session cookie names.
const (
	CookieNameSecure = "__Host-sfx_session"
	CookieNameHTTP   = "sfx_session"
)

// protoHTTPS is the HTTPS protocol identifier used in forwarded-proto checks.
const protoHTTPS = "https"

// IsBrowserRequest returns true if the request appears to be from a browser
// (Accept header contains text/html and no X-API-Key header).
func IsBrowserRequest(r *http.Request) bool {
	if r.Header.Get(HeaderXAPIKey) != "" {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// isHTTPS returns true if the request arrived over HTTPS.
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == protoHTTPS
}

// SessionCookieName returns the appropriate cookie name based on whether
// the request arrived over HTTPS.
func SessionCookieName(r *http.Request) string {
	if isHTTPS(r) {
		return CookieNameSecure
	}
	return CookieNameHTTP
}

// SetSessionCookie sets the session cookie on the response.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	secure := isHTTPS(r)
	name := CookieNameHTTP
	if secure {
		name = CookieNameSecure
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is conditional for LAN HTTP support
		Name:     name,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie clears the session cookie.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	SetSessionCookie(w, r, "", -1)
}

// ReadSessionCookie reads the session token from the cookie.
func ReadSessionCookie(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName(r))
	if err != nil {
		return ""
	}
	return c.Value
}
