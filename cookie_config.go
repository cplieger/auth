package auth

import (
	"errors"
	"net/http"
	"strings"
)

// CookiePosture determines the cookie security posture at deploy time.
// This is a DEPLOY-TIME decision, NOT per-request.
type CookiePosture int

const (
	// PostureSecure is the default: __Host- prefix + Secure + HttpOnly + SameSite=Lax.
	// Works on any HTTPS deployment including self-signed certificates.
	PostureSecure CookiePosture = iota

	// PostureInsecureLAN is for HTTP-only LAN/Docker deployments (ip:port, dockername:port).
	// Uses a non-prefixed name, no Secure flag. Explicitly opt-in only.
	PostureInsecureLAN

	// PostureForceSecure forces Secure flag even behind a TLS-terminating proxy
	// where r.TLS is nil. Requires TrustForwardedHeaders=true to detect HTTPS.
	PostureForceSecure

	// PosturePerRequest selects the cookie name and Secure flag per request,
	// driven by isHTTPS(r) (which honors TrustForwardedHeaders): __Host-<base>
	// with Secure over HTTPS, and the bare <base> without Secure over plain
	// HTTP. Intended for a single instance serving both HTTP-LAN (ip:port) and
	// HTTPS-proxied traffic. The base name stays configurable via Name.
	PosturePerRequest
)

// CookieConfig holds configurable cookie attributes for session cookies.
// The posture is a deploy-time decision — ONE stable cookie name per deployment.
type CookieConfig struct {
	// Name is the base cookie name (without __Host- prefix).
	// Default: "auth_session".
	Name string

	// Path is the cookie Path attribute. Default: "/".
	Path string

	// Domain is the cookie Domain attribute. Default: "" (unset).
	// Note: __Host- prefix requires Domain to be unset.
	Domain string

	// SameSite is the cookie SameSite attribute. Default: http.SameSiteLaxMode.
	SameSite http.SameSite

	// Posture selects the deploy-time cookie security posture.
	// Default: PostureSecure.
	Posture CookiePosture

	// TrustForwardedHeaders enables honoring X-Forwarded-Proto to detect HTTPS.
	// MUST only be enabled when the app is behind a reverse proxy that always
	// sets/overwrites this header. When false (default), only r.TLS is used.
	TrustForwardedHeaders bool
}

// Legacy constants for backward compatibility.
const (
	CookieNameSecure = "__Host-auth_session"
	CookieNameHTTP   = "auth_session"
)

// CookieNoPrefix is kept for backward compatibility in tests.
const CookieNoPrefix = "-"

// DefaultCookieConfig returns a CookieConfig with secure defaults.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Posture:  PostureSecure,
		Name:     CookieNameHTTP,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
}

// baseName returns the configured base cookie name, falling back to the
// library default when unset.
func (c *CookieConfig) baseName() string {
	if c.Name == "" {
		return CookieNameHTTP
	}
	return c.Name
}

// EffectiveName returns the ONE stable cookie name for this deployment.
// Determined entirely by Posture at config time — no per-request logic.
//
// For PosturePerRequest the actual emitted/read name varies per request (see
// CookieName / SetCookie / ReadCookie); EffectiveName returns the secure
// __Host-<base> form as the canonical name for request-less callers and
// validation.
func (c *CookieConfig) EffectiveName() string {
	base := c.baseName()
	switch c.Posture {
	case PostureInsecureLAN:
		return base
	default: // PostureSecure, PostureForceSecure, PosturePerRequest
		return "__Host-" + base
	}
}

// requestName returns the cookie name appropriate for this request. In
// PosturePerRequest mode the name depends on the request scheme (driven by
// isHTTPS, which honors TrustForwardedHeaders); in all other postures it is the
// stable EffectiveName() and the request is ignored.
func (c *CookieConfig) requestName(r *http.Request) string {
	if c.Posture == PosturePerRequest {
		base := c.baseName()
		if c.isHTTPS(r) {
			return "__Host-" + base
		}
		return base
	}
	return c.EffectiveName()
}

// effectivePath returns the resolved path.
func (c *CookieConfig) effectivePath() string {
	if c.Path != "" {
		return c.Path
	}
	return "/"
}

// effectiveSameSite returns the resolved SameSite mode.
func (c *CookieConfig) effectiveSameSite() http.SameSite {
	if c.SameSite != 0 {
		return c.SameSite
	}
	return http.SameSiteLaxMode
}

// isSecureCookie returns whether the Secure flag should be set based on posture.
func (c *CookieConfig) isSecureCookie() bool {
	return c.Posture != PostureInsecureLAN
}

// isSecureCookieForRequest returns whether the Secure flag should be set for
// this request. In PosturePerRequest mode the decision follows the request
// scheme (isHTTPS); in all other postures it follows the deploy-time posture.
func (c *CookieConfig) isSecureCookieForRequest(r *http.Request) bool {
	if c.Posture == PosturePerRequest {
		return c.isHTTPS(r)
	}
	return c.isSecureCookie()
}

// protoHTTPS is the HTTPS protocol identifier used in forwarded-proto checks.
const protoHTTPS = "https"

// isHTTPS returns true if the request arrived over HTTPS, respecting
// TrustForwardedHeaders configuration.
func (c *CookieConfig) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if c.TrustForwardedHeaders {
		return r.Header.Get("X-Forwarded-Proto") == protoHTTPS
	}
	return false
}

// CookieName returns the cookie name for this config. In PosturePerRequest mode
// the name is selected from the request scheme (__Host-<base> over HTTPS, bare
// <base> over plain HTTP); in all other postures the request is ignored and the
// stable EffectiveName() is returned.
func (c *CookieConfig) CookieName(r *http.Request) string {
	return c.requestName(r)
}

// SetCookie sets the session cookie on the response using this config.
//
// The Secure attribute follows the posture via isSecureCookieForRequest: it is
// set for every HTTPS posture and omitted only for plain-HTTP delivery, namely
// PostureInsecureLAN or PosturePerRequest over an HTTP request. Omitting Secure
// there is deliberate: a browser never sends a Secure cookie over plain HTTP,
// so forcing it would silently break sessions on HTTP-only LAN deployments. The
// default posture (PostureSecure) always sets Secure. Static analysis flags the
// conditional Secure (gosec G124, CodeQL go/cookie-secure-not-set); that is a
// documented false positive for the HTTP-LAN support, exercised by
// cookie_perrequest_test.go and redteam_test.go.
func (c *CookieConfig) SetCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is conditional for LAN HTTP / per-request support
		Name:     c.requestName(r),
		Value:    token,
		Path:     c.effectivePath(),
		Domain:   c.Domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   c.isSecureCookieForRequest(r),
		SameSite: c.effectiveSameSite(),
	})
	// Cache-Control: no-store on any response with Set-Cookie (OWASP Session Mgmt CS)
	w.Header().Set("Cache-Control", "no-store")
}

// ClearCookie clears the session cookie.
func (c *CookieConfig) ClearCookie(w http.ResponseWriter, r *http.Request) {
	c.SetCookie(w, r, "", -1)
}

// ReadCookie reads the session token from the cookie using the
// request-appropriate name (per-request in PosturePerRequest mode, otherwise
// the stable EffectiveName()).
func (c *CookieConfig) ReadCookie(r *http.Request) string {
	ck, err := r.Cookie(c.requestName(r))
	if err != nil {
		return ""
	}
	return ck.Value
}

// Validate checks that the CookieConfig fields do not contain characters
// that would cause http.SetCookie to silently produce a malformed header.
func (c *CookieConfig) Validate() error {
	name := c.EffectiveName()
	if err := validateCookieField("Name", name); err != nil {
		return err
	}
	if c.Domain != "" {
		if err := validateCookieField("Domain", c.Domain); err != nil {
			return err
		}
	}
	if c.Path != "" {
		if err := validateCookieField("Path", c.Path); err != nil {
			return err
		}
	}
	return nil
}

// validateCookieField rejects strings containing control characters or
// characters invalid in cookie attributes.
func validateCookieField(field, value string) error {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("auth: CookieConfig." + field + " contains control character")
		}
	}
	if field == "Name" {
		if strings.ContainsAny(value, " ;=,\"\\") {
			return errors.New("auth: CookieConfig." + field + " contains invalid cookie-name character")
		}
	}
	return nil
}
