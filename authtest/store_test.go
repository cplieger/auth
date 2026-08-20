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

// TestMemStoreIsolatesStoredValues pins the package's isolation guarantee: a
// value a consumer test hands in, and a value it gets back, are both its own.
// The guarantee rests on auth.User/Session/Key holding no reference-typed
// field, so a struct copy is complete; adding one silently breaks it, and this
// test is what turns that into a failure. Before v4 removed the two optional
// *time.Time fields, mutating a returned session's OIDCExpiry expired the
// STORED session, and the same held for a key's ExpiresAt.
func TestMemStoreIsolatesStoredValues(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()
	ctx := t.Context()
	now := time.Now()

	sess := &auth.Session{
		TokenHash:    "h",
		UserID:       1,
		CreatedAt:    now,
		LastActivity: now,
		OIDCExpiry:   now.Add(time.Hour),
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// Mutating the value handed IN must not reach the store.
	sess.OIDCExpiry = now.Add(-time.Hour)
	got, found, err := store.SessionByHash(ctx, "h")
	if err != nil || !found {
		t.Fatalf("SessionByHash(%q) = (_, %t, %v), want (session, true, nil)", "h", found, err)
	}
	if verr := auth.ValidateSession(got, auth.SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}, now); verr != nil {
		t.Errorf("after mutating the session passed to CreateSession, ValidateSession(stored) = %v, want nil", verr)
	}
	// Mutating the value handed OUT must not reach the store either.
	got.OIDCExpiry = now.Add(-time.Hour)
	again, _, err := store.SessionByHash(ctx, "h")
	if err != nil {
		t.Fatalf("SessionByHash(%q) second read: %v", "h", err)
	}
	if verr := auth.ValidateSession(again, auth.SessionTimeouts{Idle: time.Hour, Absolute: 24 * time.Hour}, now); verr != nil {
		t.Errorf("after mutating a returned session, ValidateSession(stored) = %v, want nil", verr)
	}

	key := &auth.Key{KeyHash: "kh", UserID: 1, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	store.AddAPIKey(key)
	key.ExpiresAt = now.Add(-time.Hour)
	gotKey, found, err := store.APIKeyByHash(ctx, "kh")
	if err != nil || !found {
		t.Fatalf("APIKeyByHash(%q) = (_, %t, %v), want (key, true, nil)", "kh", found, err)
	}
	if gotKey.ExpiresAt.Before(now) {
		t.Errorf("after mutating the key passed to AddAPIKey, stored ExpiresAt = %v, want after %v", gotKey.ExpiresAt, now)
	}
	gotKey.ExpiresAt = now.Add(-time.Hour)
	againKey, _, err := store.APIKeyByHash(ctx, "kh")
	if err != nil {
		t.Fatalf("APIKeyByHash(%q) second read: %v", "kh", err)
	}
	if againKey.ExpiresAt.Before(now) {
		t.Errorf("after mutating a returned key, stored ExpiresAt = %v, want after %v", againKey.ExpiresAt, now)
	}

	user := &auth.User{Username: "u", Role: auth.RoleUser, Enabled: true}
	store.AddUser(user)
	id := user.ID
	user.Role = auth.RoleAdmin
	gotUser, found, err := store.UserByID(ctx, id)
	if err != nil || !found {
		t.Fatalf("UserByID(%d) = (_, %t, %v), want (user, true, nil)", id, found, err)
	}
	if gotUser.Role != auth.RoleUser {
		t.Errorf("after mutating the user passed to AddUser, stored Role = %q, want %q", gotUser.Role, auth.RoleUser)
	}
	gotUser.Role = auth.RoleAdmin
	againUser, _, err := store.UserByID(ctx, id)
	if err != nil {
		t.Fatalf("UserByID(%d) second read: %v", id, err)
	}
	if againUser.Role != auth.RoleUser {
		t.Errorf("after mutating a returned user, stored Role = %q, want %q", againUser.Role, auth.RoleUser)
	}
}
