package auth

import (
	"cmp"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// CookiePosture determines the cookie security posture. Every posture except
// [PosturePerRequest] is a deploy-time decision with one stable cookie name;
// PosturePerRequest selects the name and Secure flag per request from the
// request scheme.
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

// String returns the posture's name so structured-log attributes render
// "PostureSecure" rather than the bare iota integer.
func (p CookiePosture) String() string {
	switch p {
	case PostureSecure:
		return "PostureSecure"
	case PostureInsecureLAN:
		return "PostureInsecureLAN"
	case PostureForceSecure:
		return "PostureForceSecure"
	case PosturePerRequest:
		return "PosturePerRequest"
	default:
		return fmt.Sprintf("CookiePosture(%d)", int(p))
	}
}

var _ fmt.Stringer = CookiePosture(0)

// CookieConfig holds configurable cookie attributes for session cookies.
// Under every posture except [PosturePerRequest] the deployment has ONE stable
// cookie name; PosturePerRequest alternates between the __Host--prefixed and
// bare forms of the configured base name per request scheme.
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

// defaultCookieName is the base cookie name used when CookieConfig.Name is unset.
const defaultCookieName = "auth_session"

// DefaultCookieConfig returns a CookieConfig with secure defaults.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Posture:  PostureSecure,
		Name:     defaultCookieName,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
}

// baseName returns the configured base cookie name, falling back to the
// library default when unset.
func (c *CookieConfig) baseName() string {
	return cmp.Or(c.Name, defaultCookieName)
}

// usesHostPrefix reports whether this posture emits a __Host--prefixed cookie
// name. Every posture except PostureInsecureLAN does (PostureSecure,
// PostureForceSecure, and PosturePerRequest over HTTPS). Centralizing it keeps
// the posture->prefix rule and the __Host- attribute constraints (no Domain,
// Path="/") in one place.
func (c *CookieConfig) usesHostPrefix() bool {
	return c.Posture != PostureInsecureLAN
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
	if c.usesHostPrefix() {
		return "__Host-" + base
	}
	return base
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
	return cmp.Or(c.Path, "/")
}

// effectiveSameSite returns the resolved SameSite mode.
func (c *CookieConfig) effectiveSameSite() http.SameSite {
	return cmp.Or(c.SameSite, http.SameSiteLaxMode)
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

// Validate reports whether the configuration will produce a usable session
// cookie. It returns an error when:
//
//   - Name, Domain, or Path contains a control character, or Name contains a
//     character invalid in a cookie name -- cases that would make
//     http.SetCookie emit a malformed Set-Cookie header; or
//   - the posture emits a __Host--prefixed name (every posture except
//     PostureInsecureLAN) while Domain is set or Path is not "/". Browsers
//     silently reject a __Host- cookie that carries a Domain or a non-root
//     Path, breaking every session with no server-side error.
//
// Validate is the single authority for cookie-config validity: the
// constructors ([New], [NewSessionVerifier]) call it so an
// unusable configuration fails fast at construction, and consumers assembling a
// CookieConfig by hand may call it directly.
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
	// The __Host- prefix (applied by EffectiveName for every posture except
	// PostureInsecureLAN) is only honored by browsers when the cookie sets no
	// Domain and uses Path=/. A config that sets Domain or a non-root Path under
	// such a posture emits a cookie every browser silently rejects, breaking
	// sessions while Validate() otherwise reports the config as sound.
	if c.usesHostPrefix() {
		if c.Domain != "" {
			return errors.New("auth: CookieConfig.Domain must be empty when the __Host- prefix is used (all postures except PostureInsecureLAN)")
		}
		if c.Path != "" && c.Path != "/" {
			return errors.New("auth: CookieConfig.Path must be \"/\" when the __Host- prefix is used (all postures except PostureInsecureLAN)")
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
