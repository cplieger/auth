package auth

import (
	"context"
	"testing"
)

// fakeAPIKeyStore implements APIKeyReader for fuzz testing.
type fakeAPIKeyStore struct {
	key *Key
}

func (s *fakeAPIKeyStore) APIKeyByHash(_ context.Context, hash string) (*Key, bool, error) {
	if s.key != nil && s.key.KeyHash == hash {
		return s.key, true, nil
	}
	return nil, false, nil
}

func FuzzVerifyAPIKey(f *testing.F) {
	f.Add("random-key")
	f.Add("")
	f.Add("\x00null\x00bytes")
	f.Add("ak_abcdef1234567890")

	f.Fuzz(func(t *testing.T, fuzzInput string) {
		plaintext, hash, _, _ := GenerateAPIKey("ak_")

		store := &fakeAPIKeyStore{key: &Key{KeyHash: hash, UserID: 1}}

		k, err := VerifyAPIKey(t.Context(), store, plaintext)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if k == nil {
			t.Fatal("round-trip returned nil key")
		}

		if fuzzInput == plaintext {
			return
		}
		k, err = VerifyAPIKey(t.Context(), store, fuzzInput)
		if err == nil && k != nil {
			t.Fatal("fuzzed key verified against hash")
		}
	})
}
