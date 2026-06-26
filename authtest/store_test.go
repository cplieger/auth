package authtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/cplieger/auth"
	"github.com/cplieger/auth/authtest"
)

func TestMemStore_implements_SessionStore(t *testing.T) {
	var _ auth.SessionStore = authtest.NewMemStore()
}

func TestMemStore_user_roundtrip(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()

	u := &auth.User{Username: "test", Role: auth.RoleUser, Enabled: true}
	store.AddUser(u)

	got, err := store.GetUserByID(context.Background(), u.ID)
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

	sess, err := store.GetSessionByHash(context.Background(), "hash1")
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
	ctx := context.Background()

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

	key, err := store.GetAPIKeyByHash(context.Background(), "keyhash")
	if err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if key == nil || key.Label != "test" {
		t.Fatalf("GetAPIKeyByHash = %+v, want label %q", key, "test")
	}
}
