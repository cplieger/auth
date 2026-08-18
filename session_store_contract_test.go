package auth

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// AuthenticatorStoreContractSuite runs behavioral cases against any AuthenticatorStore.
func AuthenticatorStoreContractSuite(t *testing.T, newStore func(t *testing.T) AuthenticatorStore) {
	t.Helper()

	t.Run("GetSessionByHash_missing_reports_not_found", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		sess, found, err := s.GetSessionByHash(t.Context(), "nonexistent")
		if err != nil {
			t.Fatalf("GetSessionByHash(%q) err = %v, want nil: absence is not a failure", "nonexistent", err)
		}
		if found {
			t.Errorf("GetSessionByHash(%q) found = true, want false", "nonexistent")
		}
		if sess != nil {
			t.Errorf("GetSessionByHash(%q) sess = %+v, want nil", "nonexistent", sess)
		}
	})

	t.Run("GetUserByID_missing_reports_not_found", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		user, found, err := s.GetUserByID(t.Context(), 99999)
		if err != nil {
			t.Fatalf("GetUserByID(99999) err = %v, want nil: absence is not a failure", err)
		}
		if found {
			t.Errorf("GetUserByID(99999) found = true, want false")
		}
		if user != nil {
			t.Errorf("GetUserByID(99999) user = %+v, want nil", user)
		}
	})

	t.Run("GetAPIKeyByHash_missing_reports_not_found", func(t *testing.T) {
		t.Parallel()
		s := newStore(t)
		key, found, err := s.GetAPIKeyByHash(t.Context(), "nonexistent")
		if err != nil {
			t.Fatalf("GetAPIKeyByHash(%q) err = %v, want nil: absence is not a failure", "nonexistent", err)
		}
		if found {
			t.Errorf("GetAPIKeyByHash(%q) found = true, want false", "nonexistent")
		}
		if key != nil {
			t.Errorf("GetAPIKeyByHash(%q) key = %+v, want nil", "nonexistent", key)
		}
	})
}

// SessionStoreContractSuite is an alias for backward compatibility.
var SessionStoreContractSuite = AuthenticatorStoreContractSuite

// SessionStoreContractTest is an alias for backward compatibility.
var SessionStoreContractTest = AuthenticatorStoreContractSuite

func TestFakeSessionStore_contract(t *testing.T) {
	t.Parallel()
	AuthenticatorStoreContractSuite(t, func(_ *testing.T) AuthenticatorStore {
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
	got, _, err := store.GetUserByID(ctx, u.ID)
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
	gotSess, _, err := store.GetSessionByHash(ctx, "test-hash")
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if gotSess == nil || gotSess.UserID != u.ID {
		t.Fatalf("got %+v", gotSess)
	}

	if err := store.CreateAPIKey(ctx, &Key{KeyHash: "key-hash", UserID: u.ID, Label: "k"}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	gotKey, _, err := store.GetAPIKeyByHash(ctx, "key-hash")
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
			s, _, err := db.GetSessionByHash(ctx, h)
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
