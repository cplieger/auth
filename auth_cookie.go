package auth

import (
	"net/http"
	"strings"
)

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

// SessionCookieName returns the stable cookie name using the default CookieConfig.
func SessionCookieName(_ *http.Request) string {
	return defaultCookieConfig.EffectiveName()
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
