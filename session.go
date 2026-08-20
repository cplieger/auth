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
//
// It cannot fail, and so returns no error: since Go 1.24 [crypto/rand.Read] is
// documented never to return an error — it fills its argument entirely and
// crashes the program irrecoverably rather than reporting a failure a caller
// could mishandle. An always-nil error here would propagate to every token
// constructor below and invite the one fallback that must never exist in an
// auth library: degrading to a weaker source when "randomness failed".
func generateRandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b) // never returns an error (Go 1.24+); it crashes instead
	return hex.EncodeToString(b)
}

// GenerateSessionToken generates a cryptographically random session token
// (256 bits / 32 bytes). It returns the hex-encoded plaintext token and
// its SHA-256 hash (also hex-encoded). It cannot fail; see
// [generateRandomHex].
func GenerateSessionToken() (plaintext, hash string) {
	plaintext = generateRandomHex(32)
	return plaintext, SessionHash(plaintext)
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
