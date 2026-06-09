package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestProperty_APIKeyHashVerificationRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		plaintext, returnedHash, _, _, err := GenerateAPIKey("ak_")
		if err != nil {
			t.Fatalf("GenerateAPIKey error: %v", err)
		}

		h := sha256.Sum256([]byte(plaintext))
		computedHash := hex.EncodeToString(h[:])

		if subtle.ConstantTimeCompare([]byte(computedHash), []byte(returnedHash)) != 1 {
			t.Fatalf("hash mismatch")
		}

		other := plaintext + "x"
		otherH := sha256.Sum256([]byte(other))
		otherHash := hex.EncodeToString(otherH[:])
		if subtle.ConstantTimeCompare([]byte(otherHash), []byte(returnedHash)) == 1 {
			t.Fatalf("different key produced same hash")
		}
	})
}

func TestProperty_APIKeyFormatAndUniqueness(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 20).Draw(t, "n")
		plaintexts := make(map[string]struct{}, n)
		hashes := make(map[string]struct{}, n)

		for i := range n {
			plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
			if err != nil {
				t.Fatalf("GenerateAPIKey[%d] error: %v", i, err)
			}

			if len(plaintext) < 3 || plaintext[:3] != "ak_" {
				t.Fatalf("key does not start with ak_")
			}
			randomPart := plaintext[3:]
			if len(randomPart) < 64 {
				t.Fatalf("random portion length %d < 64", len(randomPart))
			}
			if _, err := hex.DecodeString(randomPart); err != nil {
				t.Fatalf("random portion is not valid hex: %v", err)
			}
			if prefix != plaintext[:8] {
				t.Fatalf("prefix mismatch")
			}
			if suffix != plaintext[len(plaintext)-4:] {
				t.Fatalf("suffix mismatch")
			}
			if _, dup := plaintexts[plaintext]; dup {
				t.Fatalf("duplicate plaintext")
			}
			plaintexts[plaintext] = struct{}{}
			if _, dup := hashes[hash]; dup {
				t.Fatalf("duplicate hash")
			}
			hashes[hash] = struct{}{}
		}
	})
}

func TestVerifyAPIKey_error_paths(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := context.Background()

	user := &User{Username: "keyuser", PasswordHash: "dummy", Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix, Label: "test",
	}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  string
	}{
		{"nonexistent", "ak_0000000000000000000000000000000000000000000000000000000000000000"},
		{"wrong key", plaintext + "x"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := VerifyAPIKey(ctx, db, tc.key)
			if !errors.Is(err, ErrInvalidAPIKey) {
				t.Errorf("error = %v, want ErrInvalidAPIKey", err)
			}
			if got != nil {
				t.Errorf("got = %+v, want nil", got)
			}
		})
	}

	got, err := VerifyAPIKey(ctx, db, plaintext)
	if err != nil {
		t.Fatalf("VerifyAPIKey(valid) error: %v", err)
	}
	if got == nil {
		t.Fatal("VerifyAPIKey(valid) = nil")
	}
}

func TestVerifyAPIKey_expired(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := context.Background()

	user := &User{Username: "keyuser", PasswordHash: "dummy", Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	past := time.Now().Add(-time.Hour)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix,
		Label: "expired", ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	_, err = VerifyAPIKey(ctx, db, plaintext)
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("VerifyAPIKey(expired) = %v, want ErrInvalidAPIKey", err)
	}
}

func TestVerifyAPIKey_not_expired(t *testing.T) {
	t.Parallel()
	db := newFakeSessionStore()
	ctx := context.Background()

	user := &User{Username: "keyuser", PasswordHash: "dummy", Role: "admin", Enabled: true}
	if err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	plaintext, hash, prefix, suffix, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	future := time.Now().Add(time.Hour)
	if err := db.CreateAPIKey(ctx, &Key{
		UserID: user.ID, KeyHash: hash, KeyPrefix: prefix, KeySuffix: suffix,
		Label: "valid", ExpiresAt: &future,
	}); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	got, err := VerifyAPIKey(ctx, db, plaintext)
	if err != nil {
		t.Fatalf("VerifyAPIKey(valid) error: %v", err)
	}
	if got == nil {
		t.Fatal("VerifyAPIKey(valid) = nil")
	}
}

func TestGenerateAPIKey_custom_prefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		prefix string
	}{
		{"standard", "ak_"},
		{"custom", "myapp_"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plaintext, hash, displayPrefix, displaySuffix, err := GenerateAPIKey(tt.prefix)
			if err != nil {
				t.Fatalf("GenerateAPIKey(%q) error: %v", tt.prefix, err)
			}
			if tt.prefix != "" && plaintext[:len(tt.prefix)] != tt.prefix {
				t.Errorf("plaintext %q does not start with prefix %q", plaintext, tt.prefix)
			}
			if hash == "" {
				t.Error("hash is empty")
			}
			if displayPrefix == "" {
				t.Error("displayPrefix is empty")
			}
			if displaySuffix == "" {
				t.Error("displaySuffix is empty")
			}
		})
	}
}

// looseAPIKeyStore returns its key for any hash, simulating a store that
// performs a loose or buggy lookup not anchored to an exact hash match.
type looseAPIKeyStore struct {
	key *Key
}

func (s *looseAPIKeyStore) GetAPIKeyByHash(_ context.Context, _ string) (*Key, error) {
	return s.key, nil
}

func TestVerifyAPIKey_rejects_hash_mismatch(t *testing.T) {
	t.Parallel()
	plaintext, _, _, _, err := GenerateAPIKey("ak_")
	if err != nil {
		t.Fatalf("GenerateAPIKey error: %v", err)
	}
	// The store returns a record whose stored hash does NOT match the hash of
	// the presented key. VerifyAPIKey must reject it rather than trust the
	// store's lookup.
	store := &looseAPIKeyStore{key: &Key{KeyHash: "not-the-right-hash", UserID: 7}}
	if _, err := VerifyAPIKey(context.Background(), store, plaintext); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("VerifyAPIKey(hash mismatch) = %v, want ErrInvalidAPIKey", err)
	}
}
