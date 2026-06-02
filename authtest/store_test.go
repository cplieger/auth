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

func TestMemStore_roundtrip(t *testing.T) {
	t.Parallel()
	store := authtest.NewMemStore()
	ctx := context.Background()

	u := &auth.User{Username: "test", Role: auth.RoleUser, Enabled: true}
	store.AddUser(u)

	got, err := store.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Username != "test" {
		t.Fatalf("got %+v", got)
	}

	now := time.Now()
	store.AddSession(&auth.Session{
		TokenHash: "hash1", UserID: u.ID, CreatedAt: now, LastActivity: now,
	})

	sess, err := store.GetSessionByHash(ctx, "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if sess == nil {
		t.Fatal("session not found")
	}

	// Test UpdateSessionActivity
	later := now.Add(5 * time.Minute)
	if err := store.UpdateSessionActivity(ctx, "hash1", later); err != nil {
		t.Fatal(err)
	}
	sess, _ = store.GetSessionByHash(ctx, "hash1")
	if !sess.LastActivity.Equal(later) {
		t.Errorf("LastActivity = %v, want %v", sess.LastActivity, later)
	}

	// Test API key
	store.AddAPIKey(&auth.Key{KeyHash: "keyhash", UserID: u.ID, Label: "test"})
	key, err := store.GetAPIKeyByHash(ctx, "keyhash")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil || key.Label != "test" {
		t.Fatalf("got %+v", key)
	}
}
