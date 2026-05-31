package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"testing"

	"pgregory.net/rapid"
)

func TestProperty_APIKeyHashVerificationRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		plaintext, returnedHash, _, _, err := GenerateAPIKey()
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
			plaintext, hash, prefix, suffix, err := GenerateAPIKey()
			if err != nil {
				t.Fatalf("GenerateAPIKey[%d] error: %v", i, err)
			}

			if len(plaintext) < 4 || plaintext[:4] != "sfx_" {
				t.Fatalf("key does not start with sfx_")
			}
			randomPart := plaintext[4:]
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

	plaintext, hash, prefix, suffix, err := GenerateAPIKey()
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
		{"nonexistent", "sfx_0000000000000000000000000000000000000000000000000000000000000000"},
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
