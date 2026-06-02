package auth

import (
	"errors"
	"net/http"
	"strings"
)

// cookieDefaultPrefix is the default __Host- cookie prefix for HTTPS.
const cookieDefaultPrefix = "__Host-"

// CookieConfig holds configurable cookie attributes for session cookies.
// Zero-value fields use secure defaults preserving current behavior:
// __Host-auth_session (HTTPS) / auth_session (HTTP), Path="/", SameSite=Lax,
// HttpOnly=true, Secure=auto (true when HTTPS).
type CookieConfig struct {
	// Secure overrides the Secure attribute. Default: auto (true when HTTPS).
	// If explicitly set to true, Secure is always set regardless of protocol.
	Secure *bool

	// Name is the base cookie name (without __Host- prefix).
	// Default: "auth_session".
	Name string

	// Prefix controls the cookie name prefix for HTTPS requests.
	// Default: "__Host-". Set to CookieNoPrefix to disable prefixing.
	Prefix string

	// Path is the cookie Path attribute. Default: "/".
	Path string

	// Domain is the cookie Domain attribute. Default: "" (unset).
	// Note: __Host- prefix requires Domain to be unset; if Domain is set,
	// the prefix is automatically omitted.
	Domain string

	// SameSite is the cookie SameSite attribute. Default: http.SameSiteLaxMode.
	SameSite http.SameSite
}

// CookieNoPrefix is the sentinel value for CookieConfig.Prefix to explicitly
// disable cookie name prefixing.
const CookieNoPrefix = "-"

// DefaultCookieConfig returns a CookieConfig with defaults matching the
// library's original behavior.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:     CookieNameHTTP,
		Prefix:   cookieDefaultPrefix,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
}

// Validate checks that the CookieConfig fields do not contain characters
// that would cause http.SetCookie to silently produce an empty or malformed
// Set-Cookie header (e.g., control characters, semicolons, spaces in Name).
func (c *CookieConfig) Validate() error {
	name := c.effectiveName()
	if err := validateCookieField("Name", name); err != nil {
		return err
	}
	if c.Prefix != "" && c.Prefix != CookieNoPrefix {
		if err := validateCookieField("Prefix", c.Prefix); err != nil {
			return err
		}
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
// characters invalid in cookie attributes (semicolons, spaces in names).
func validateCookieField(field, value string) error {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("auth: CookieConfig." + field + " contains control character")
		}
	}
	if field == "Name" || field == "Prefix" {
		if strings.ContainsAny(value, " ;=,\"\\") {
			return errors.New("auth: CookieConfig." + field + " contains invalid cookie-name character")
		}
	}
	return nil
}

// effectiveName returns the resolved base name.
func (c *CookieConfig) effectiveName() string {
	if c.Name != "" {
		return c.Name
	}
	return CookieNameHTTP
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

// effectivePrefix returns the resolved prefix. __Host- prefix is suppressed
// when Domain is set (per cookie prefix spec).
func (c *CookieConfig) effectivePrefix() string {
	if c.Domain != "" {
		return ""
	}
	if c.Prefix == CookieNoPrefix {
		return ""
	}
	if c.Prefix != "" {
		return c.Prefix
	}
	return cookieDefaultPrefix
}

// resolveSecure returns whether the Secure flag should be set.
func (c *CookieConfig) resolveSecure(https bool) bool {
	if c.Secure != nil {
		return *c.Secure
	}
	return https
}

// CookieName returns the full cookie name for the given request using this config.
func (c *CookieConfig) CookieName(r *http.Request) string {
	if isHTTPS(r) && c.effectivePrefix() != "" {
		return c.effectivePrefix() + c.effectiveName()
	}
	return c.effectiveName()
}

// SetCookie sets the session cookie on the response using this config.
func (c *CookieConfig) SetCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	https := isHTTPS(r)
	name := c.effectiveName()
	if https && c.effectivePrefix() != "" {
		name = c.effectivePrefix() + name
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is conditional for LAN HTTP support
		Name:     name,
		Value:    token,
		Path:     c.effectivePath(),
		Domain:   c.Domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   c.resolveSecure(https),
		SameSite: c.effectiveSameSite(),
	})
}

// ClearCookie clears the session cookie.
func (c *CookieConfig) ClearCookie(w http.ResponseWriter, r *http.Request) {
	c.SetCookie(w, r, "", -1)
}

// ReadCookie reads the session token from the cookie.
func (c *CookieConfig) ReadCookie(r *http.Request) string {
	name := c.CookieName(r)
	ck, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return ck.Value
}
