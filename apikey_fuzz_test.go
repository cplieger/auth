package auth

import (
	"context"
	"testing"
	"time"
)

// fakeAPIKeyStore implements APIKeyReader for fuzz testing.
type fakeAPIKeyStore struct {
	key *Key
}

func (s *fakeAPIKeyStore) GetAPIKeyByHash(_ context.Context, hash string) (*Key, error) {
	if s.key != nil && s.key.KeyHash == hash {
		return s.key, nil
	}
	return nil, nil
}

func FuzzVerifyAPIKey(f *testing.F) {
	f.Add("random-key")
	f.Add("")
	f.Add("\x00null\x00bytes")
	f.Add("ak_abcdef1234567890")

	f.Fuzz(func(t *testing.T, fuzzInput string) {
		// Generate a real API key
		plaintext, hash, _, _, err := GenerateAPIKey("ak_")
		if err != nil {
			t.Skipf("GenerateAPIKey error: %v", err)
		}

		store := &fakeAPIKeyStore{key: &Key{KeyHash: hash, UserID: 1}}

		// Round-trip: correct key must verify
		k, err := VerifyAPIKey(context.Background(), store, plaintext)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if k == nil {
			t.Fatal("round-trip returned nil key")
		}

		// Fuzzed input must not verify (unless equal to plaintext)
		if fuzzInput == plaintext {
			return
		}
		k, err = VerifyAPIKey(context.Background(), store, fuzzInput)
		if err == nil && k != nil {
			t.Fatal("fuzzed key verified against hash")
		}
	})
}

func FuzzVerifyAPIKeyExpired(f *testing.F) {
	f.Add("test")

	f.Fuzz(func(t *testing.T, fuzzInput string) {
		plaintext, hash, _, _, err := GenerateAPIKey("ak_")
		if err != nil {
			t.Skipf("GenerateAPIKey error: %v", err)
		}
		expired := time.Now().Add(-time.Hour)
		store := &fakeAPIKeyStore{key: &Key{KeyHash: hash, UserID: 1, ExpiresAt: &expired}}

		// Expired key should fail even with correct plaintext
		_, err = VerifyAPIKey(context.Background(), store, plaintext)
		if err == nil {
			t.Fatal("expired key should not verify")
		}
		_ = fuzzInput
	})
}
