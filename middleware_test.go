package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestProperty_SessionInvalidationOnPasswordChange(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		db := newFakeSessionStore()
		ctx := context.Background()

		user := &User{
			Username:     "testuser",
			PasswordHash: "dummy",
			Role:         "admin",
			Enabled:      true,
		}
		if err := db.CreateUser(ctx, user); err != nil {
			rt.Fatalf("CreateUser: %v", err)
		}

		n := rapid.IntRange(1, 10).Draw(rt, "numSessions")
		hashes := make([]string, n)
		for i := range n {
			_, hash, err := GenerateSessionToken()
			if err != nil {
				rt.Fatalf("GenerateSessionToken[%d]: %v", i, err)
			}
			hashes[i] = hash
			sess := &Session{
				TokenHash:  hash,
				UserID:     user.ID,
				AuthMethod: "password",
				IPAddress:  "127.0.0.1",
			}
			if err := db.CreateSession(ctx, sess); err != nil {
				rt.Fatalf("CreateSession[%d]: %v", i, err)
			}
		}

		keepIdx := rapid.IntRange(0, n-1).Draw(rt, "keepIdx")
		exceptHash := hashes[keepIdx]

		if err := db.DeleteUserSessions(ctx, user.ID, exceptHash); err != nil {
			rt.Fatalf("DeleteUserSessions: %v", err)
		}

		remaining := 0
		for _, h := range hashes {
			s, err := db.GetSessionByHash(ctx, h)
			if err != nil {
				rt.Fatalf("GetSessionByHash(%s): %v", h, err)
			}
			if s != nil {
				remaining++
				if h != exceptHash {
					rt.Fatalf("session %s should have been deleted", h)
				}
			}
		}
		if remaining != 1 {
			rt.Fatalf("expected 1 remaining session, got %d", remaining)
		}
	})
}

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

func TestProperty_APIKeyRoleInheritance(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		db := newFakeSessionStore()
		ctx := context.Background()

		role := rapid.SampledFrom([]string{"admin", "user"}).Draw(rt, "role")
		username := fmt.Sprintf("user_%s", rapid.StringMatching(`[a-z]{4,8}`).Draw(rt, "username"))

		user := &User{
			Username:     username,
			PasswordHash: "dummy",
			Role:         Role(role),
			Enabled:      true,
		}
		if err := db.CreateUser(ctx, user); err != nil {
			rt.Fatalf("CreateUser: %v", err)
		}

		plaintext, hash, prefix, suffix, err := GenerateAPIKey()
		if err != nil {
			rt.Fatalf("GenerateAPIKey: %v", err)
		}
		apiKey := &Key{
			UserID:    user.ID,
			KeyHash:   hash,
			KeyPrefix: prefix,
			KeySuffix: suffix,
			Label:     "test",
		}
		if err := db.CreateAPIKey(ctx, apiKey); err != nil {
			rt.Fatalf("CreateAPIKey: %v", err)
		}

		verified, err := VerifyAPIKey(ctx, db, plaintext)
		if err != nil {
			rt.Fatalf("VerifyAPIKey: %v", err)
		}
		if verified.UserID != user.ID {
			rt.Fatalf("API key user ID mismatch: got %d, want %d", verified.UserID, user.ID)
		}

		resolvedUser, err := db.GetUserByID(ctx, verified.UserID)
		if err != nil {
			rt.Fatalf("GetUserByID: %v", err)
		}
		if resolvedUser.Role != Role(role) {
			rt.Fatalf("role mismatch: got %s, want %s", resolvedUser.Role, role)
		}
	})
}

func TestIsBrowserRequest_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		accept string
		apiKey string
		want   bool
	}{
		{"browser html", "text/html,application/xhtml+xml", "", true},
		{"browser with wildcard", "text/html, */*", "", true},
		{"api client json", "application/json", "", false},
		{"api key overrides browser", "text/html", "sfx_abc123", false},
		{"empty accept", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if tt.apiKey != "" {
				r.Header.Set("X-API-Key", tt.apiKey)
			}
			got := IsBrowserRequest(r)
			if got != tt.want {
				t.Errorf("IsBrowserRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsHTTPS_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		forwardedProto string
		useTLS         bool
		want           bool
	}{
		{"plain http", "", false, false},
		{"tls connection", "", true, true},
		{"forwarded https", "https", false, true},
		{"forwarded http", "http", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.useTLS {
				r.TLS = &tls.ConnectionState{}
			}
			if tt.forwardedProto != "" {
				r.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			}
			got := isHTTPS(r)
			if got != tt.want {
				t.Errorf("isHTTPS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionCookieName_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want string
		tls  bool
	}{
		{"http", CookieNameHTTP, false},
		{"https", CookieNameSecure, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := SessionCookieName(r); got != tt.want {
				t.Errorf("SessionCookieName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetSessionCookie_sets_correct_attributes(t *testing.T) {
	t.Parallel()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	SetSessionCookie(w, r, "tok123", 3600)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != CookieNameHTTP {
		t.Errorf("name = %q, want %q", c.Name, CookieNameHTTP)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly = false")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
}

func TestClearSessionCookie_sets_negative_max_age(t *testing.T) {
	t.Parallel()
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ClearSessionCookie(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("MaxAge = %d, want -1", cookies[0].MaxAge)
	}
}

func TestReadSessionCookie_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cookieName string
		value      string
		want       string
	}{
		{"present", CookieNameHTTP, "mytoken", "mytoken"},
		{"no cookie", "", "", ""},
		{"wrong name", "other", "val", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.cookieName != "" {
				r.AddCookie(&http.Cookie{Name: tt.cookieName, Value: tt.value})
			}
			if got := ReadSessionCookie(r); got != tt.want {
				t.Errorf("ReadSessionCookie() = %q, want %q", got, tt.want)
			}
		})
	}
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
	ctx := context.Background()

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

	a := &Authenticator{Store: db, IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour}
	r, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameHTTP, Value: plaintext})

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
	ctx := context.Background()

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

	a := &Authenticator{Store: db, IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour}
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameHTTP, Value: plaintext})

	_, _, gotErr := a.Authenticate(r)
	if gotErr == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestAuthenticate_api_key_header(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := context.Background()

	user := &User{Username: "apiuser", PasswordHash: "dummy", Role: "user", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatal(err)
	}

	a := &Authenticator{Store: db, IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour}
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
	a := &Authenticator{Store: newFakeSessionStore(), IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour}
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	_, _, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Errorf("error = %v, want ErrUnauthenticated", gotErr)
	}
}

func TestAuthenticate_disabled_user_session(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := context.Background()

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

	a := &Authenticator{Store: db, IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour}
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieNameHTTP, Value: plaintext})

	_, _, gotErr := a.Authenticate(r)
	if !errors.Is(gotErr, ErrUnauthenticated) {
		t.Errorf("error = %v, want ErrUnauthenticated", gotErr)
	}
}

func TestRequireAuth_unauthenticated_browser_redirects(t *testing.T) {
	t.Parallel()
	a := &Authenticator{Store: newFakeSessionStore(), IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour}
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
	a := &Authenticator{Store: newFakeSessionStore(), IdleTimeout: time.Hour, AbsTimeout: 24 * time.Hour}
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
