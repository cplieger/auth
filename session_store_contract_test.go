package auth

import (
	"context"
	"testing"
	"time"
)

// AuthStoreContractSuite runs behavioral cases against any AuthStore.
func AuthStoreContractSuite(t *testing.T, newStore func(t *testing.T) AuthStore) {
	t.Helper()

	t.Run("GetSessionByHash_missing_returns_nil_nil", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		sess, err := s.GetSessionByHash(context.Background(), "nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sess != nil {
			t.Fatalf("expected nil, got %+v", sess)
		}
	})

	t.Run("GetUserByID_missing_returns_nil_nil", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		user, err := s.GetUserByID(context.Background(), 99999)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if user != nil {
			t.Fatalf("expected nil, got %+v", user)
		}
	})

	t.Run("GetAPIKeyByHash_missing_returns_nil_nil", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		key, err := s.GetAPIKeyByHash(context.Background(), "nonexistent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != nil {
			t.Fatalf("expected nil, got %+v", key)
		}
	})
}

// SessionStoreContractSuite is an alias for backward compatibility.
var SessionStoreContractSuite = AuthStoreContractSuite

// SessionStoreContractTest is an alias for backward compatibility.
var SessionStoreContractTest = AuthStoreContractSuite

func TestFakeSessionStore_contract(t *testing.T) {
	t.Parallel()
	AuthStoreContractSuite(t, func(_ *testing.T) AuthStore {
		return newFakeSessionStore()
	})
}

func TestFakeSessionStore_roundtrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeSessionStore()

	u := &User{Username: "contract-user", PasswordHash: "hash"}
	if err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := store.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got == nil || got.Username != "contract-user" {
		t.Fatalf("got %+v", got)
	}

	if err := store.CreateSession(ctx, &Session{
		TokenHash: "test-hash", UserID: u.ID, CreatedAt: time.Now(), LastActivity: time.Now(),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	gotSess, err := store.GetSessionByHash(ctx, "test-hash")
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if gotSess == nil || gotSess.UserID != u.ID {
		t.Fatalf("got %+v", gotSess)
	}

	if err := store.CreateAPIKey(ctx, &Key{KeyHash: "key-hash", UserID: u.ID, Label: "k"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	gotKey, err := store.GetAPIKeyByHash(ctx, "key-hash")
	if err != nil {
		t.Fatalf("GetAPIKeyByHash: %v", err)
	}
	if gotKey == nil || gotKey.Label != "k" {
		t.Fatalf("got %+v", gotKey)
	}
}
