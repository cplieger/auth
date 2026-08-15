package auth

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// AuthStoreContractSuite runs behavioral cases against any AuthStore.
func AuthStoreContractSuite(t *testing.T, newStore func(t *testing.T) AuthStore) {
	t.Helper()

	t.Run("GetSessionByHash_missing_returns_nil_nil", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		sess, err := s.GetSessionByHash(t.Context(), "nonexistent")
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
		user, err := s.GetUserByID(t.Context(), 99999)
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
		key, err := s.GetAPIKeyByHash(t.Context(), "nonexistent")
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
	ctx := t.Context()
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

// TestProperty_SessionInvalidationOnPasswordChange verifies the store contract
// that DeleteUserSessions removes every session for a user except the one
// explicitly preserved (the caller's current session on a password change).
func TestProperty_SessionInvalidationOnPasswordChange(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		db := newFakeSessionStore()
		ctx := t.Context()

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
