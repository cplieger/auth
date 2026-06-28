package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

// Token errors.
var (
	ErrTokenExpired = errors.New("auth: token expired")
	ErrTokenInvalid = errors.New("auth: token invalid")
)

// CSRF token format: nonce[16] ∥ issuedAt[8] ∥ HMAC-SHA256(key, nonce ∥ sessionHash ∥ issuedAt)
// Total: 16 + 8 + 32 = 56 bytes.
const (
	csrfNonceLen     = 16
	csrfTimestampLen = 8
	csrfTokenLen     = csrfNonceLen + csrfTimestampLen + sha256.Size
)

// --- Session Token Rotation ---

// RotateSessionToken generates a new session token, returning the new
// plaintext, new hash, and old hash. The caller is responsible for
// atomically replacing the session record in the store (delete old hash,
// insert new hash with same session data).
func RotateSessionToken(oldPlaintext string) (newPlaintext, newHash, oldHash string, err error) {
	oldHash = SessionHash(oldPlaintext)
	newPlaintext, newHash, err = GenerateSessionToken()
	if err != nil {
		return "", "", "", err
	}
	return newPlaintext, newHash, oldHash, nil
}

// --- CSRF Token Helpers (signed double-submit with random nonce) ---

// CSRFToken generates a CSRF token bound to the given session hash using
// HMAC-SHA256 with a random 16-byte nonce per OWASP signed double-submit.
// Format: base64url(nonce[16] ∥ issuedAt[8] ∥ HMAC-SHA256(key, nonce ∥ sessionHash ∥ issuedAt))
func CSRFToken(key []byte, sessionHash string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("auth: CSRF key must not be empty")
	}
	nonce := make([]byte, csrfNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	issuedAt := make([]byte, csrfTimestampLen)
	binary.BigEndian.PutUint64(issuedAt, uint64(time.Now().Unix())) //nolint:gosec // G115: Unix() is non-negative in practice

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write([]byte(sessionHash))
	mac.Write(issuedAt)
	sig := mac.Sum(nil)

	token := make([]byte, 0, csrfTokenLen)
	token = append(token, nonce...)
	token = append(token, issuedAt...)
	token = append(token, sig...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// VerifyCSRFToken verifies a CSRF token against the session hash and checks
// that it has not expired (maxAge duration from creation).
func VerifyCSRFToken(key []byte, sessionHash, token string, maxAge time.Duration) error {
	if len(key) == 0 {
		return ErrTokenInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != csrfTokenLen {
		return ErrTokenInvalid
	}
	nonce := raw[:csrfNonceLen]
	issuedAt := raw[csrfNonceLen : csrfNonceLen+csrfTimestampLen]
	sig := raw[csrfNonceLen+csrfTimestampLen:]

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write([]byte(sessionHash))
	mac.Write(issuedAt)
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return ErrTokenInvalid
	}

	created := time.Unix(int64(binary.BigEndian.Uint64(issuedAt)), 0) //nolint:gosec // G115: timestamp fits in int64
	if time.Since(created) > maxAge {
		return ErrTokenExpired
	}
	return nil
}

// --- Password-Reset / Email-Verification Token Primitives ---

// GenerateOpaqueToken generates a cryptographically random opaque token
// suitable for password-reset or email-verification flows. Returns the
// plaintext token (to send to the user) and its SHA-256 hash (to store
// in the database).
func GenerateOpaqueToken() (plaintext, hash string, err error) {
	plaintext, err = generateRandomHex(32)
	if err != nil {
		return "", "", err
	}
	return plaintext, HexSHA256(plaintext), nil
}

// VerifyOpaqueToken checks that the plaintext token matches the stored hash
// and that the token has not expired. Returns nil on success.
func VerifyOpaqueToken(plaintext, storedHash string, expiresAt time.Time) error {
	computed := HexSHA256(plaintext)
	if subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) != 1 {
		return ErrTokenInvalid
	}
	if time.Now().After(expiresAt) {
		return ErrTokenExpired
	}
	return nil
}
