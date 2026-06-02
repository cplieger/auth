package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Sentinel errors for session operations.
var (
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionNotFound = errors.New("session not found")
)

// generateRandomHex returns n cryptographically random bytes, hex-encoded.
func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateSessionToken generates a cryptographically random session token
// (256 bits / 32 bytes). It returns the hex-encoded plaintext token and
// its SHA-256 hash (also hex-encoded).
func GenerateSessionToken() (plaintext, hash string, err error) {
	plaintext, err = generateRandomHex(32)
	if err != nil {
		return "", "", err
	}
	return plaintext, SessionHash(plaintext), nil
}

// ValidateSession checks whether a session is still valid given the idle
// and absolute timeout durations.
func ValidateSession(sess *Session, idleTimeout, absTimeout time.Duration, now time.Time) error {
	if sess == nil {
		return ErrSessionNotFound
	}
	if now.Sub(sess.LastActivity) > idleTimeout {
		return ErrSessionExpired
	}
	if now.Sub(sess.CreatedAt) > absTimeout {
		return ErrSessionExpired
	}
	if sess.OIDCExpiry != nil && now.After(*sess.OIDCExpiry) {
		return ErrSessionExpired
	}
	return nil
}

// HexSHA256 returns the hex-encoded SHA-256 hash of s.
func HexSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// SessionHash returns the hex-encoded SHA-256 hash of a plaintext token.
func SessionHash(token string) string {
	return HexSHA256(token)
}
