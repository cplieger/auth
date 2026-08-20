package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"
)

// ErrInvalidAPIKey is returned when an API key cannot be verified.
var ErrInvalidAPIKey = errors.New("invalid API key")

// GenerateAPIKey generates a new API key with 256 bits of entropy.
// The keyPrefix is prepended to the random hex string (e.g. "ak_").
// It returns the plaintext key, its SHA-256 hash, a display prefix
// (first 8 chars), and a display suffix (last 4 chars). It cannot fail; see
// [generateRandomHex].
func GenerateAPIKey(keyPrefix string) (plaintext, hash, displayPrefix, displaySuffix string) {
	plaintext = keyPrefix + generateRandomHex(32)
	hash = APIKeyHash(plaintext)
	displayPrefix = plaintext[:min(8, len(plaintext))]
	displaySuffix = plaintext[max(0, len(plaintext)-4):]
	return plaintext, hash, displayPrefix, displaySuffix
}

// VerifyAPIKey hashes the provided key, looks it up in the store, and
// returns the matching APIKey record. Returns ErrInvalidAPIKey if the key
// is not found or has expired.
func VerifyAPIKey(ctx context.Context, store APIKeyReader, key string) (*Key, error) {
	hash := APIKeyHash(key)
	apiKey, found, err := store.APIKeyByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrInvalidAPIKey
	}
	// Defense in depth: confirm the stored hash exactly equals the computed
	// hash in constant time. Guards against a store that performs a loose or
	// prefix lookup and removes timing variance from the comparison.
	if subtle.ConstantTimeCompare([]byte(hash), []byte(apiKey.KeyHash)) != 1 {
		return nil, ErrInvalidAPIKey
	}
	if !apiKey.ExpiresAt.IsZero() && time.Now().After(apiKey.ExpiresAt) {
		return nil, ErrInvalidAPIKey
	}
	return apiKey, nil
}

// APIKeyHash returns the hex-encoded SHA-256 hash of a key string.
func APIKeyHash(key string) string {
	return HexSHA256(key)
}
