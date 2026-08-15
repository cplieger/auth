package authtest_test

import (
	"testing"
	"time"

	"github.com/cplieger/auth/v2"
	"github.com/cplieger/auth/v2/authtest"
)

func TestMemStore_implements_SessionStore(t *testing.T) {
	var _ auth.SessionStore = authtest.NewMemStore()
}

func TestMemStore_user_roundtrip(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()

	u := &auth.User{Username: "test", Role: auth.RoleUser, Enabled: true}
	store.AddUser(u)

	got, err := store.GetUserByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got == nil || got.Username != "test" {
		t.Fatalf("GetUserByID = %+v, want username %q", got, "test")
	}
}

func TestMemStore_session_roundtrip(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()

	now := time.Now()
	store.AddSession(&auth.Session{TokenHash: "hash1", CreatedAt: now, LastActivity: now})

	sess, err := store.GetSessionByHash(t.Context(), "hash1")
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if sess == nil {
		t.Fatal("GetSessionByHash = nil, want stored session")
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

	sess, err := store.GetSessionByHash(ctx, "hash1")
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if !sess.LastActivity.Equal(later) {
		t.Errorf("LastActivity = %v, want %v", sess.LastActivity, later)
	}
}

func TestMemStore_apikey_roundtrip(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()

	store.AddAPIKey(&auth.Key{KeyHash: "keyhash", Label: "test"})

	key, err := store.GetAPIKeyByHash(t.Context(), "keyhash")
	if err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if key == nil || key.Label != "test" {
		t.Fatalf("GetAPIKeyByHash = %+v, want label %q", key, "test")
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
		s, err := store.GetSessionByHash(ctx, hash)
		if err != nil {
			t.Fatalf("GetSessionByHash(%s): %v", hash, err)
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
	s, err := store.GetSessionByHash(ctx, "h")
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if s != nil {
		t.Error("session present after DeleteSession, want deleted")
	}
}

func TestMemStore_missing_lookups_return_nil_without_error(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()
	ctx := t.Context()

	if u, err := store.GetUserByID(ctx, 999); err != nil || u != nil {
		t.Errorf("GetUserByID(absent) = (%+v, %v), want (nil, nil)", u, err)
	}
	if k, err := store.GetAPIKeyByHash(ctx, "absent"); err != nil || k != nil {
		t.Errorf("GetAPIKeyByHash(absent) = (%+v, %v), want (nil, nil)", k, err)
	}
	if s, err := store.GetSessionByHash(ctx, "absent"); err != nil || s != nil {
		t.Errorf("GetSessionByHash(absent) = (%+v, %v), want (nil, nil)", s, err)
	}
}
