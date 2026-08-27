package auth

import (
	"net/http"
	"strings"
)

// IsBrowserRequest returns true if the request appears to be from a browser
// (Accept header contains text/html and no X-API-Key header).
func IsBrowserRequest(r *http.Request) bool {
	if r.Header.Get(HeaderXAPIKey) != "" {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
