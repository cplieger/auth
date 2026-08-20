package authtest_test

import (
	"testing"
	"time"

	"github.com/cplieger/auth/v4"
	"github.com/cplieger/auth/v4/authtest"
)

func TestMemStore_implements_SessionStore(t *testing.T) {
	var _ auth.SessionStore = authtest.NewMemStore()
}

func TestMemStore_user_roundtrip(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()

	u := &auth.User{Username: "test", Role: auth.RoleUser, Enabled: true}
	store.AddUser(u)

	got, _, err := store.UserByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("UserByID: %v", err)
	}
	if got == nil || got.Username != "test" {
		t.Fatalf("UserByID = %+v, want username %q", got, "test")
	}
}

func TestMemStore_session_roundtrip(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()

	now := time.Now()
	store.AddSession(&auth.Session{TokenHash: "hash1", CreatedAt: now, LastActivity: now})

	sess, _, err := store.SessionByHash(t.Context(), "hash1")
	if err != nil {
		t.Fatalf("SessionByHash: %v", err)
	}
	if sess == nil {
		t.Fatal("SessionByHash = nil, want stored session")
	}
}

func TestMemStore_UpdateSessionActivity(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()
	ctx := t.Context()

	now := time.Now()
	store.AddSession(&auth.Session{TokenHash: "hash1", CreatedAt: now, LastActivity: now})

	later := now.Add(5 * time.Minute)
	if err := store.UpdateSessionActivity(ctx, "hash1", later); err != nil {
		t.Fatalf("UpdateSessionActivity: %v", err)
	}

	sess, _, err := store.SessionByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("SessionByHash: %v", err)
	}
	if !sess.LastActivity.Equal(later) {
		t.Errorf("LastActivity = %v, want %v", sess.LastActivity, later)
	}
}

func TestMemStore_apikey_roundtrip(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()

	store.AddAPIKey(&auth.Key{KeyHash: "keyhash", Label: "test"})

	key, _, err := store.APIKeyByHash(t.Context(), "keyhash")
	if err != nil {
		t.Fatalf("APIKeyByHash: %v", err)
	}
	if key == nil || key.Label != "test" {
		t.Fatalf("APIKeyByHash = %+v, want label %q", key, "test")
	}
}

func TestMemStore_DeleteUserSessions_keepsExcepted(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()
	ctx := t.Context()
	now := time.Now()

	store.AddSession(&auth.Session{TokenHash: "u1-keep", UserID: 1, CreatedAt: now, LastActivity: now})
	store.AddSession(&auth.Session{TokenHash: "u1-drop", UserID: 1, CreatedAt: now, LastActivity: now})
	store.AddSession(&auth.Session{TokenHash: "u2-keep", UserID: 2, CreatedAt: now, LastActivity: now})

	if err := store.DeleteUserSessions(ctx, 1, "u1-keep"); err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}

	assertPresent := func(hash string, want bool) {
		t.Helper()
		s, _, err := store.SessionByHash(ctx, hash)
		if err != nil {
			t.Fatalf("SessionByHash(%s): %v", hash, err)
		}
		if (s != nil) != want {
			t.Errorf("session %s present=%v, want %v", hash, s != nil, want)
		}
	}
	assertPresent("u1-keep", true)  // excepted: survives
	assertPresent("u1-drop", false) // same user, not excepted: deleted
	assertPresent("u2-keep", true)  // different user: untouched
}

func TestMemStore_DeleteSession_removes(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()
	ctx := t.Context()
	now := time.Now()
	if err := store.CreateSession(ctx, &auth.Session{TokenHash: "h", UserID: 1, CreatedAt: now, LastActivity: now}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := store.DeleteSession(ctx, "h"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	s, _, err := store.SessionByHash(ctx, "h")
	if err != nil {
		t.Fatalf("SessionByHash: %v", err)
	}
	if s != nil {
		t.Error("session present after DeleteSession, want deleted")
	}
}

func TestMemStore_missing_lookups_report_not_found(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()
	ctx := t.Context()

	if u, found, err := store.UserByID(ctx, 999); err != nil || found || u != nil {
		t.Errorf("UserByID(999) = (%+v, %t, %v), want (nil, false, nil)", u, found, err)
	}
	if k, found, err := store.APIKeyByHash(ctx, "absent"); err != nil || found || k != nil {
		t.Errorf("APIKeyByHash(%q) = (%+v, %t, %v), want (nil, false, nil)", "absent", k, found, err)
	}
	if s, found, err := store.SessionByHash(ctx, "absent"); err != nil || found || s != nil {
		t.Errorf("SessionByHash(%q) = (%+v, %t, %v), want (nil, false, nil)", "absent", s, found, err)
	}
}
