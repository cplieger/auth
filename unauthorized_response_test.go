package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequireAuth_UnauthorizedHook_ReplacesBothBranches confirms that a hook
// installed via WithUnauthorizedResponse owns the entire unauthorized
// response: it runs for API-shaped and browser-shaped requests alike, and the
// default redirect/envelope is not written.
func TestRequireAuth_UnauthorizedHook_ReplacesBothBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		accept  string
		browser bool
	}{
		{name: "api request", accept: "", browser: false},
		{name: "browser request", accept: "text/html", browser: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			called := 0
			a := mustAuthenticator(t, newFakeSessionStore(),
				WithUnauthorizedResponse(func(w http.ResponseWriter, _ *http.Request) {
					called++
					w.WriteHeader(http.StatusTeapot)
				}))

			r := httptest.NewRequest(http.MethodGet, "/private", nil)
			if tc.accept != "" {
				r.Header.Set("Accept", tc.accept)
			}
			rec := httptest.NewRecorder()

			user, _, ok := a.RequireAuth(rec, r)
			if ok || user != nil {
				t.Fatalf("RequireAuth = (%v, ok=%v), want unauthenticated", user, ok)
			}
			if called != 1 {
				t.Fatalf("hook called %d times, want 1", called)
			}
			if rec.Code != http.StatusTeapot {
				t.Fatalf("status = %d, want %d (hook-owned response)", rec.Code, http.StatusTeapot)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("Location = %q, want empty (default redirect must not run)", loc)
			}
		})
	}
}

// TestRequireAuth_UnauthorizedHook_NotCalledWhenAuthenticated confirms the
// hook is an unauthorized-path concern only.
func TestRequireAuth_UnauthorizedHook_NotCalledWhenAuthenticated(t *testing.T) {
	t.Parallel()
	called := 0
	a := mustAuthenticator(t, newFakeSessionStore(),
		WithBypass(func() bool { return true }),
		WithUnauthorizedResponse(func(http.ResponseWriter, *http.Request) { called++ }))

	rec := httptest.NewRecorder()
	user, _, ok := a.RequireAuth(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !ok || user == nil {
		t.Fatal("RequireAuth under bypass should authenticate")
	}
	if called != 0 {
		t.Fatalf("hook called %d times on the authenticated path, want 0", called)
	}
}
