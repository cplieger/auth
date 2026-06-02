package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ErrUnauthenticated is returned when no valid credential is found.
var ErrUnauthenticated = errors.New("unauthenticated")

// Authenticator resolves an HTTP request to an authenticated user.
// Create with [NewAuthenticator].
type Authenticator struct {
	store SessionStore
	cfg   authConfig
}

// NewAuthenticator creates an Authenticator with the given session store and options.
// The store is required; options configure logger, bypass, cookie, timeouts, etc.
// If no idle/absolute timeout is provided, defaults of 1h and 24h are applied.
func NewAuthenticator(store SessionStore, opts ...Option) *Authenticator {
	cfg := authConfig{}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	cfg.defaults()
	return &Authenticator{store: store, cfg: cfg}
}

// syntheticAdminUser is the user injected when BypassAuth is true.
var syntheticAdminUser = &User{
	ID:       0,
	Username: string(RoleAdmin),
	Role:     RoleAdmin,
	Enabled:  true,
}

// Authenticate checks session cookie first, then API key header, then API key
// query param. Returns the user and session hash, or [ErrUnauthenticated].
func (a *Authenticator) Authenticate(r *http.Request) (*User, string, error) {
	if a.cfg.bypass != nil && a.cfg.bypass() {
		return syntheticAdminUser, "", nil
	}

	ctx := r.Context()
	for _, v := range a.verifiers() {
		user, hash, err := v.Verify(ctx, r)
		if err != nil {
			return nil, "", err
		}
		if user != nil {
			return user, hash, nil
		}
	}
	return nil, "", ErrUnauthenticated
}

// RequireAuth checks authentication and returns the user. If not
// authenticated, it writes the appropriate response (401 or redirect)
// and returns ok=false.
func (a *Authenticator) RequireAuth(w http.ResponseWriter, r *http.Request) (*User, string, bool) {
	user, sessHash, err := a.Authenticate(r)
	if err != nil {
		if IsBrowserRequest(r) {
			http.Redirect(w, r, a.loginPath()+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		} else {
			writeUnauthorized(w, r)
		}
		return nil, "", false
	}
	return user, sessHash, true
}

// loginPath returns the configured login path or "/login".
func (a *Authenticator) loginPath() string {
	if a.cfg.loginPath != "" {
		return a.cfg.loginPath
	}
	return "/login"
}

// verifiers returns the ordered list of credential verifiers.
func (a *Authenticator) verifiers() []CredentialVerifier {
	return []CredentialVerifier{
		NewSessionVerifier(a.store, WithLogger(a.cfg.logger), WithIdleTimeout(a.cfg.idleTimeout), WithAbsTimeout(a.cfg.absTimeout), WithCookie(a.cfg.cookie)),
		NewAPIKeyVerifier(a.store),
	}
}

// HasRole reports whether the user is authorized for the given role.
func HasRole(user *User, role Role) bool {
	return user.Role == role || user.Role == RoleAdmin
}

// ValidateRedirectURI ensures the URI is a safe relative path.
// Returns "/" if the URI is empty, absolute, contains a scheme/host,
// or uses backslash path separators (open-redirect prevention).
func ValidateRedirectURI(uri string) string {
	if uri == "/" {
		return "/"
	}
	if len(uri) < 2 || uri[0] != '/' || uri[1] == '/' || uri[1] == '\\' {
		return "/"
	}
	if strings.Contains(uri, "://") {
		return "/"
	}
	if strings.ContainsAny(uri, "\\") {
		return "/"
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "/"
	}
	return uri
}

// CanDisableAuthMethod checks whether disabling the given auth method would
// leave the user with no viable authentication method.
func CanDisableAuthMethod(method Method, hasPassword bool, passkeyCount int, oidcEnabled, oidcLinked bool) bool {
	remaining := 0
	if method != MethodPassword && hasPassword {
		remaining++
	}
	if method != MethodPasskey && passkeyCount > 0 {
		remaining++
	}
	if method != MethodOIDC && oidcEnabled && oidcLinked {
		remaining++
	}
	return remaining > 0
}

// writeUnauthorized writes a 401 JSON error response.
func writeUnauthorized(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": ErrUnauthenticated.Error(),
		"code":  "auth_session_required",
	})
}
