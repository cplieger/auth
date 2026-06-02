package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// ErrInvalidAPIKey is returned when an API key cannot be verified.
var ErrInvalidAPIKey = errors.New("invalid API key")

// GenerateAPIKey generates a new API key with 256 bits of entropy.
// The keyPrefix is prepended to the random hex string (e.g. "ak_").
// It returns the plaintext key, its SHA-256 hash, a display prefix
// (first 8 chars), and a display suffix (last 4 chars).
func GenerateAPIKey(keyPrefix string) (plaintext, hash, displayPrefix, displaySuffix string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", "", err
	}
	plaintext = keyPrefix + hex.EncodeToString(b)
	hash = APIKeyHash(plaintext)
	displayPrefix = plaintext[:min(8, len(plaintext))]
	displaySuffix = plaintext[max(0, len(plaintext)-4):]
	return plaintext, hash, displayPrefix, displaySuffix, nil
}

// VerifyAPIKey hashes the provided key, looks it up in the store, and
// returns the matching APIKey record. Returns ErrInvalidAPIKey if the key
// is not found or has expired.
func VerifyAPIKey(ctx context.Context, store SessionStore, key string) (*Key, error) {
	hash := APIKeyHash(key)
	apiKey, err := store.GetAPIKeyByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	if apiKey == nil {
		return nil, ErrInvalidAPIKey
	}
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, ErrInvalidAPIKey
	}
	return apiKey, nil
}

// APIKeyHash returns the hex-encoded SHA-256 hash of a key string.
func APIKeyHash(key string) string {
	return HexSHA256(key)
}
