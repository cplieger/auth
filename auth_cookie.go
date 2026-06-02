package auth

import (
	"net/http"
	"strings"
)

// Session cookie names (legacy constants for backward compatibility).
const (
	CookieNameSecure = "__Host-auth_session"
	CookieNameHTTP   = "auth_session"
)

// protoHTTPS is the HTTPS protocol identifier used in forwarded-proto checks.
const protoHTTPS = "https"

// defaultCookieConfig is the package-level default used by the free functions.
var defaultCookieConfig = DefaultCookieConfig()

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
// the request arrived over HTTPS. Uses the default CookieConfig.
func SessionCookieName(r *http.Request) string {
	return defaultCookieConfig.CookieName(r)
}

// SetSessionCookie sets the session cookie on the response using the default CookieConfig.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	defaultCookieConfig.SetCookie(w, r, token, maxAge)
}

// ClearSessionCookie clears the session cookie using the default CookieConfig.
func ClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	defaultCookieConfig.ClearCookie(w, r)
}

// ReadSessionCookie reads the session token from the cookie using the default CookieConfig.
func ReadSessionCookie(r *http.Request) string {
	return defaultCookieConfig.ReadCookie(r)
}
