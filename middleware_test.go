package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestProperty_LastAuthMethodGuard(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		hasPassword := rapid.Bool().Draw(t, "hasPassword")
		passkeyCount := rapid.IntRange(0, 5).Draw(t, "passkeyCount")
		oidcEnabled := rapid.Bool().Draw(t, "oidcEnabled")
		oidcLinked := rapid.Bool().Draw(t, "oidcLinked")

		viable := 0
		if hasPassword {
			viable++
		}
		if passkeyCount > 0 {
			viable++
		}
		if oidcEnabled && oidcLinked {
			viable++
		}

		methods := []Method{MethodPassword, MethodPasskey, MethodOIDC}
		for _, method := range methods {
			canDisable := CanDisableAuthMethod(method, hasPassword, passkeyCount, oidcEnabled, oidcLinked)

			remainingViable := viable
			switch method {
			case MethodPassword:
				if hasPassword {
					remainingViable--
				}
			case MethodPasskey:
				if passkeyCount > 0 {
					remainingViable--
				}
			case MethodOIDC:
				if oidcEnabled && oidcLinked {
					remainingViable--
				}
			}

			if remainingViable > 0 && !canDisable {
				t.Fatalf("should allow disabling %s", method)
			}
			if remainingViable <= 0 && canDisable {
				t.Fatalf("should NOT allow disabling %s (last method)", method)
			}
		}
	})
}

func TestHasRole_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		userRole Role
		required Role
		want     bool
	}{
		{"admin accessing admin", "admin", "admin", true},
		{"admin accessing user", "admin", "user", true},
		{"user accessing user", "user", "user", true},
		{"user accessing admin", "user", "admin", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user := &User{Role: tt.userRole}
			if got := HasRole(user, tt.required); got != tt.want {
				t.Errorf("HasRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateRedirectURI_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{"empty", "", "/"},
		{"root", "/", "/"},
		{"relative path", "/dashboard", "/dashboard"},
		{"two-char path", "/a", "/a"},
		{"absolute http", "http://evil.com", "/"},
		{"protocol-relative", "//evil.com", "/"},
		{"scheme in path", "/foo://bar", "/"},
		{"no leading slash", "evil.com", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidateRedirectURI(tt.uri); got != tt.want {
				t.Errorf("ValidateRedirectURI(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}
}

func TestAuthenticate_session_cookie_valid(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "sessuser", PasswordHash: "dummy", Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameSecure, Value: plaintext})

	gotUser, gotHash, gotErr := a.Authenticate(r)
	if gotErr != nil {
		t.Fatalf("error = %v", gotErr)
	}
	if gotUser.ID != user.ID {
		t.Errorf("user ID = %d, want %d", gotUser.ID, user.ID)
	}
	if gotHash != hash {
		t.Errorf("hash = %q, want %q", gotHash, hash)
	}
}

func TestAuthenticate_expired_session_falls_through(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "expuser", PasswordHash: "dummy", Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-25 * time.Hour)
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: old, LastActivity: old.Add(23 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameSecure, Value: plaintext})

	_, _, gotErr := a.Authenticate(r)
	if gotErr == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestAuthenticate_api_key_header(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "apiuser", PasswordHash: "dummy", Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/api/search", nil)
	r.Header.Set("X-API-Key", plaintext)

	gotUser, _, gotErr := a.Authenticate(r)
	if gotErr != nil {
		t.Fatalf("error = %v", gotErr)
	}
	if gotUser.ID != user.ID {
		t.Errorf("user ID = %d, want %d", gotUser.ID, user.ID)
	}
}

func TestAuthenticate_no_credentials(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	_, _, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Errorf("error = %v, want ErrUnauthenticated", gotErr)
	}
}

func TestAuthenticate_disabled_user_session(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "disabled", PasswordHash: "dummy", Role: "user", Enabled: false}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameSecure, Value: plaintext})

	_, _, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Errorf("error = %v, want ErrUnauthenticated", gotErr)
	}
}

func TestRequireAuth_unauthenticated_browser_redirects(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	_, _, ok := a.RequireAuth(w, r)
	if ok {
		t.Fatal("expected ok=false")
	}
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusFound)
	}
}

func TestRequireAuth_unauthenticated_api_returns_401(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	_, _, ok := a.RequireAuth(w, r)
	if ok {
		t.Fatal("expected ok=false")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthenticate_api_key_query_param_rejected(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "queryuser", PasswordHash: "dummy", Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	// A valid key supplied only via the URL query parameter must NOT authenticate:
	// keys are accepted via the X-Api-Key header only (CWE-598: a key in the query
	// string leaks into access logs, browser history, and the Referer header).
	r, _ := http.NewRequest(http.MethodGet, "/api/search?api_key="+plaintext, nil)

	gotUser, _, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Fatalf("Authenticate(api_key query) error = %v, want ErrUnauthenticated", gotErr)
	}
	if gotUser != nil {
		t.Errorf("Authenticate(api_key query) user = %+v, want nil (query-param keys rejected)", gotUser)
	}
}

func TestAuthenticate_invalid_api_key(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", "ak_invalid_key_value")

	_, _, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Errorf("Authenticate(invalid key) error = %v, want ErrUnauthenticated", gotErr)
	}
}

func TestAuthenticate_disabled_user_api_key(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "disabledapi", PasswordHash: "dummy", Role: "user", Enabled: false}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", plaintext)

	_, _, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Errorf("Authenticate(disabled user API key) error = %v, want ErrUnauthenticated", gotErr)
	}
}

func TestRequireAuth_authenticated_returns_user(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "authuser", PasswordHash: "dummy", Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/api/search", nil)
	r.Header.Set("X-API-Key", plaintext)
	w := httptest.NewRecorder()

	gotUser, _, ok := a.RequireAuth(w, r)
	if !ok {
		t.Fatal("RequireAuth() returned ok=false for authenticated request")
	}
	if gotUser.ID != user.ID {
		t.Errorf("RequireAuth() user ID = %d, want %d", gotUser.ID, user.ID)
	}
}

func TestAuthenticate_session_not_found_falls_through(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameSecure, Value: "nonexistent-session-token"})

	_, _, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Errorf("Authenticate(stale session cookie) error = %v, want ErrUnauthenticated", gotErr)
	}
}

func TestAuthenticate_stale_session_falls_through_to_api_key(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := t.Context()

	user := &User{Username: "fallthrough_user", PasswordHash: "dummy", Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/api/search", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameSecure, Value: "stale-session-token"})
	r.Header.Set("X-API-Key", plaintext)

	gotUser, _, gotErr := a.Authenticate(r)
	if gotErr != nil {
		t.Fatalf("Authenticate(stale session + valid API key) error = %v, want nil", gotErr)
	}
	if gotUser.ID != user.ID {
		t.Errorf("Authenticate(stale session + valid API key) user ID = %d, want %d", gotUser.ID, user.ID)
	}
}

func TestAuthenticator_LoginPath_custom(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour), WithLoginPath("/auth/signin"))
	r, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	_, _, ok := a.RequireAuth(w, r)
	if ok {
		t.Fatal("expected ok=false")
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/signin") {
		t.Errorf("Location = %q, want prefix /auth/signin", loc)
	}
}

func TestAuthenticator_LoginPath_default(t *testing.T) {
	t.Parallel()
	a := mustAuthenticator(t, newFakeSessionStore(), WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour))
	r, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	_, _, ok := a.RequireAuth(w, r)
	if ok {
		t.Fatal("expected ok=false")
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Errorf("Location = %q, want prefix /login", loc)
	}
}

func TestAuthenticator_Logger_used(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	db := newFakeSessionStore()
	ctx := t.Context()

	// A disabled user with an otherwise-valid session makes the default
	// session verifier emit a debug record; it must go to the injected logger.
	user := &User{Username: "disabled", Role: RoleUser, Enabled: false}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := db.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: "password",
		IPAddress: "127.0.0.1", CreatedAt: now, LastActivity: now,
	}); err != nil {
		t.Fatal(err)
	}

	a := mustAuthenticator(t, db, WithIdleTimeout(time.Hour), WithAbsTimeout(24*time.Hour), WithLogger(logger))
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameSecure, Value: plaintext})

	if _, _, err := a.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate(disabled user) error = %v, want ErrUnauthenticated", err)
	}
	if !strings.Contains(buf.String(), "disabled user attempted session auth") {
		t.Errorf("injected logger captured no session-verifier log; got %q", buf.String())
	}
}

func TestValidateRedirectURI_rejects_backslash_and_malformed(t *testing.T) {
	t.Parallel()
	// Backslash-bearing and malformed-escape URIs are open-redirect vectors
	// (browsers fold "/\" to "//"); each must collapse to the safe root path.
	for _, tt := range []struct {
		name string
		uri  string
	}{
		{"backslash prefix", "/\\evil.com"},
		{"backslash in path", "/foo\\bar"},
		{"backslash before slash", "/\\/evil.com"},
		{"invalid percent-escape", "/%zz"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ValidateRedirectURI(tt.uri); got != "/" {
				t.Errorf("ValidateRedirectURI(%q) = %q, want %q", tt.uri, got, "/")
			}
		})
	}
}

func TestAuthenticate_bypass(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()

	on := mustAuthenticator(t, db, WithBypass(func() bool { return true }))
	gotUser, _, err := on.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("Authenticate(bypass enabled) error = %v, want nil", err)
	}
	if gotUser == nil || gotUser.Role != RoleAdmin {
		t.Fatalf("Authenticate(bypass enabled) = %+v, want a synthetic admin user", gotUser)
	}

	off := mustAuthenticator(t, db, WithBypass(func() bool { return false }))
	if _, _, err := off.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate(bypass disabled, no credentials) error = %v, want ErrUnauthenticated", err)
	}
}

func TestNewAuthenticator_bypass_logs_production_warning(t *testing.T) {
	t.Parallel()

	// Construction with a hook: one Info notice, never the WARN — an
	// installed hook is routinely inactive (hot-reloadable dev flag that is
	// off), and warning at boot would cry wolf on every start.
	var active strings.Builder
	a := mustAuthenticator(t, newFakeSessionStore(),
		WithBypass(func() bool { return true }),
		WithLogger(slog.New(slog.NewTextHandler(&active, nil))),
	)
	if got := active.String(); !strings.Contains(got, "bypass hook installed") || !strings.Contains(got, "level=INFO") {
		t.Errorf("WithBypass construction did not emit the Info install notice; log = %q", got)
	}
	if got := active.String(); strings.Contains(got, "level=WARN") {
		t.Errorf("WithBypass construction emitted a WARN before any request was granted; log = %q", got)
	}

	// First actually-granted request: the WARN fires exactly once.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, _, err := a.Authenticate(req); err != nil {
		t.Fatalf("Authenticate(bypass active) error = %v", err)
	}
	if got := active.String(); !strings.Contains(got, "authentication bypass is active") || !strings.Contains(got, "level=WARN") {
		t.Errorf("first granted bypass did not emit the WARN production-safety warning; log = %q", got)
	}
	before := strings.Count(active.String(), "authentication bypass is active")
	if _, _, err := a.Authenticate(req); err != nil {
		t.Fatalf("Authenticate(bypass active, second) error = %v", err)
	}
	if after := strings.Count(active.String(), "authentication bypass is active"); after != before {
		t.Errorf("second granted bypass duplicated the WARN (%d -> %d occurrences), want once per process", before, after)
	}

	// Installed but INACTIVE hook: requests authenticate normally and the
	// WARN never fires.
	var inactive strings.Builder
	off := mustAuthenticator(t, newFakeSessionStore(),
		WithBypass(func() bool { return false }),
		WithLogger(slog.New(slog.NewTextHandler(&inactive, nil))),
	)
	if _, _, err := off.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate(bypass inactive) error = %v, want ErrUnauthenticated", err)
	}
	if got := inactive.String(); strings.Contains(got, "level=WARN") {
		t.Errorf("inactive bypass hook emitted a WARN; log = %q", got)
	}

	// No hook at all: no bypass lines of either level.
	var noBypass strings.Builder
	_ = mustAuthenticator(t, newFakeSessionStore(),
		WithLogger(slog.New(slog.NewTextHandler(&noBypass, nil))),
	)
	if got := noBypass.String(); strings.Contains(got, "bypass") {
		t.Errorf("Authenticator without WithBypass mentioned bypass in logs; log = %q", got)
	}
}

func TestHasRole_nilUser_failsClosed(t *testing.T) {
	t.Parallel()
	// A nil principal must fail closed (false), never panic: HasRole guards an
	// authorization decision and a nil user means "not authenticated".
	if HasRole(nil, RoleUser) {
		t.Error("HasRole(nil, RoleUser) = true, want false (fail closed)")
	}
	if HasRole(nil, RoleAdmin) {
		t.Error("HasRole(nil, RoleAdmin) = true, want false (fail closed)")
	}
}

// errVerifier is a CredentialVerifier that always returns a backend error,
// exercising the non-ErrUnauthenticated error path of Authenticate/RequireAuth.
type errVerifier struct{ err error }

func (e errVerifier) Verify(context.Context, *http.Request) (*User, string, error) {
	return nil, "", e.err
}

func TestAuthenticator_injectedVerifierError_failsClosed(t *testing.T) {
	t.Parallel()
	// A verifier that returns a backend error must fail closed: Authenticate
	// propagates the error (not ErrUnauthenticated) and RequireAuth denies the
	// request (ok=false, 401) rather than treating the error as success.
	wantErr := errors.New("backend down")
	a := mustAuthenticator(t, newFakeSessionStore(), WithVerifiers([]CredentialVerifier{
		errVerifier{err: wantErr},
	}))

	if _, _, err := a.Authenticate(httptest.NewRequest(http.MethodGet, "/api/x", nil)); !errors.Is(err, wantErr) {
		t.Fatalf("Authenticate() error = %v, want %v", err, wantErr)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	if _, _, ok := a.RequireAuth(w, r); ok {
		t.Fatal("RequireAuth() ok = true on verifier error, want false (fail closed)")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("RequireAuth() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
