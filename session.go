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

// SessionTimeouts groups the idle and absolute session timeouts into one
// value. The two durations always travel together and would otherwise sit as
// adjacent same-typed parameters, where a silent swap makes the idle timeout
// effectively unbounded; the field names make each value's role explicit at
// the call site. Both fields are required: the zero value — including a
// partial literal that omits one field — expires every session instantly
// (any positive elapsed time exceeds a zero timeout), and a zero pair passed
// to CleanupExpiredSessions deletes every session row. It fails closed
// (lockout, never a bypass).
type SessionTimeouts struct {
	// Idle is the maximum time since the session's last activity.
	Idle time.Duration
	// Absolute is the maximum time since the session was created.
	Absolute time.Duration
}

// ValidateSession checks whether a session is still valid given the idle
// and absolute timeouts.
func ValidateSession(sess *Session, timeouts SessionTimeouts, now time.Time) error {
	if sess == nil {
		return ErrSessionNotFound
	}
	if now.Sub(sess.LastActivity) > timeouts.Idle {
		return ErrSessionExpired
	}
	if now.Sub(sess.CreatedAt) > timeouts.Absolute {
		return ErrSessionExpired
	}
	if !sess.OIDCExpiry.IsZero() && now.After(sess.OIDCExpiry) {
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
