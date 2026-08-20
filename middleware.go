package auth

import (
	"cmp"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ErrUnauthenticated is returned when no valid credential is found.
var ErrUnauthenticated = errors.New("unauthenticated")

// AuthenticatorStore is the composed interface needed by [Authenticator] —
// session lookup, user lookup, and API key lookup. It names the consumer it
// serves, matching [SessionVerifierStore] and [APIKeyVerifierStore], which are
// the per-verifier subsets this interface unions.
type AuthenticatorStore interface {
	SessionReader
	SessionActivityUpdater
	UserReader
	APIKeyReader
}

// Authenticator resolves an HTTP request to an authenticated user.
// Create with [New].
type Authenticator struct {
	store            AuthenticatorStore
	defaultVerifiers []CredentialVerifier
	cfg              authConfig
	// bypassWarned dedupes the loud production-safety warning: it fires on
	// the FIRST request the bypass hook actually grants, not on construction
	// (a hook is routinely installed but inactive — e.g. a hot-reloadable
	// dev flag that is off — and warning then would cry wolf on every boot).
	bypassWarned sync.Once
}

// New creates an Authenticator with the given store and options.
// The store must implement SessionReader, UserReader, and APIKeyReader. It
// returns an error when the assembled configuration is unusable (see
// [CookieConfig.Validate] and [WithActivityThrottle]). If no idle/absolute
// timeout is provided, defaults of 1h and 24h are applied.
func New(store AuthenticatorStore, opts ...Option) (*Authenticator, error) {
	cfg := authConfig{}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	a := &Authenticator{store: store, cfg: cfg}
	if cfg.bypass != nil {
		// Installation alone is not bypass: the hook may be (and usually is)
		// inactive. The WARN fires once, on the first actually-granted
		// request (see Authenticate), so a warning in the log always means
		// synthetic admin access WAS handed out.
		a.logger().Info("auth: authentication bypass hook installed; requests are bypassed only while it reports true")
	}
	// Build the default chain once (avoids per-request allocation). It is only
	// consulted when no explicit chain was injected via WithVerifiers. The
	// verifier is built from the cfg already validated above, so its error is
	// unreachable here; propagate it rather than discard it.
	sv, err := NewSessionVerifier(store,
		WithLogger(cfg.logger),
		WithIdleTimeout(cfg.idleTimeout),
		WithAbsTimeout(cfg.absTimeout),
		WithCookie(cfg.cookie),
		WithActivityThrottle(cfg.activityThrottle),
		WithTimeoutSource(cfg.timeoutSource),
	)
	if err != nil {
		return nil, err
	}
	a.defaultVerifiers = []CredentialVerifier{
		sv,
		NewAPIKeyVerifier(store, WithLogger(cfg.logger)),
	}
	return a, nil
}

// syntheticAdminUser is the VALUE copied for each request the configured
// bypass function (see [WithBypass]) grants. It is deliberately not a *User:
// handing every bypassed request one shared pointer makes the granted
// principal process-global mutable state, so a consumer that annotates "its"
// user (an audit field, a role downgrade) silently rewrites the principal
// every later bypassed request receives. Authenticate copies it per call.
var syntheticAdminUser = User{
	ID:       0,
	Username: string(RoleAdmin),
	Role:     RoleAdmin,
	Enabled:  true,
}

// Authenticate resolves the request to a user by running the credential
// verifier chain in order. The default chain checks the session cookie first,
// then the API key (accepted only via the X-Api-Key header, never a URL query
// parameter -- CWE-598). It returns the user and session hash, or
// [ErrUnauthenticated] when no verifier authenticates the request.
//
// Every returned *User is the caller's to keep: on the bypass path it is a
// fresh copy of the synthetic admin, and on the credential paths it is
// whatever the store returned.
func (a *Authenticator) Authenticate(r *http.Request) (*User, string, error) {
	if a.cfg.bypass != nil && a.cfg.bypass() {
		a.bypassWarned.Do(func() {
			a.logger().Warn("auth: authentication bypass is active; matching requests are granted synthetic admin access and must never be enabled in production")
		})
		// new(expr) (Go 1.26): a fresh User per request, so no consumer can
		// mutate the principal handed to any other request. User holds no
		// pointer, slice or map field, so this copy is a complete one.
		return new(syntheticAdminUser), "", nil
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
// authenticated, it writes the appropriate response and returns ok=false. The
// default response is a 302 redirect to the login path for browser requests
// and a 401 JSON envelope otherwise; a hook installed via
// [WithUnauthorizedResponse] replaces both branches.
func (a *Authenticator) RequireAuth(w http.ResponseWriter, r *http.Request) (*User, string, bool) {
	user, sessHash, err := a.Authenticate(r)
	if err != nil {
		if !errors.Is(err, ErrUnauthenticated) {
			a.logger().Warn("auth: authentication backend error", "error", err)
		}
		switch {
		case a.cfg.unauthorized != nil:
			a.cfg.unauthorized(w, r)
		case IsBrowserRequest(r):
			http.Redirect(w, r, a.loginPath()+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		default:
			writeUnauthorized(w, r)
		}
		return nil, "", false
	}
	return user, sessHash, true
}

// loginPath returns the configured login path or "/login".
func (a *Authenticator) loginPath() string {
	return cmp.Or(a.cfg.loginPath, "/login")
}

// logger returns the configured logger or slog.Default().
func (a *Authenticator) logger() *slog.Logger {
	if a.cfg.logger != nil {
		return a.cfg.logger
	}
	return slog.Default()
}

// verifiers returns the ordered list of credential verifiers. When an explicit
// chain was injected via [WithVerifiers], it is used; otherwise the default
// session + API-key chain (built once in [New]) is returned.
func (a *Authenticator) verifiers() []CredentialVerifier {
	if len(a.cfg.verifiers) > 0 {
		return a.cfg.verifiers
	}
	return a.defaultVerifiers
}

// HasRole reports whether the user is authorized for the given role.
func HasRole(user *User, role Role) bool {
	// Mirror the existing nil-guard convention in ValidateSession; fail-closed
	// for a nil principal rather than panicking in an authz primitive.
	if user == nil {
		return false
	}
	return user.Role == role || user.Role == RoleAdmin
}

// ValidateRedirectURI ensures the URI is a safe relative path.
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
	if strings.Contains(uri, "\\") {
		return "/"
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "/"
	}
	return uri
}

// MethodAvailability describes which authentication methods are currently
// viable for one user. The three method signals would otherwise sit as
// adjacent same-typed bool parameters, where a silent swap flips which method
// counts as remaining; the field names make each value's role explicit at the
// call site. The zero value reports no method available, so
// [CanDisableMethod] refuses every disable; an omitted field undercounts the
// remaining methods and can only make the answer more conservative (fails
// closed).
type MethodAvailability struct {
	// PasskeyCount is the number of passkeys registered to the user.
	PasskeyCount int
	// HasPassword reports whether the user has a password set.
	HasPassword bool
	// OIDCEnabled reports whether OIDC login is enabled server-wide.
	OIDCEnabled bool
	// OIDCLinked reports whether the user has a linked OIDC identity.
	OIDCLinked bool
}

// CanDisableMethod checks whether disabling the given auth method would
// leave the user with no viable authentication method.
func CanDisableMethod(method Method, avail MethodAvailability) bool {
	remaining := 0
	if method != MethodPassword && avail.HasPassword {
		remaining++
	}
	if method != MethodPasskey && avail.PasskeyCount > 0 {
		remaining++
	}
	if method != MethodOIDC && avail.OIDCEnabled && avail.OIDCLinked {
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
