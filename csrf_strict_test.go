package auth

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestVerifyCSRFToken_RejectsExtraBytes(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sessHash := "test-session"
	token, err := CSRFToken(key, sessHash)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 0xFF, 0xFE, 0xFD)
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	if err := VerifyCSRFToken(key, sessHash, tampered, time.Hour); err == nil {
		t.Fatal("expected error for CSRF token with extra trailing bytes")
	}
}

func TestVerifyCSRFToken_RejectsTruncated(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sessHash := "test-session"
	token, err := CSRFToken(key, sessHash)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	truncated := base64.RawURLEncoding.EncodeToString(raw[:len(raw)-1])

	if err := VerifyCSRFToken(key, sessHash, truncated, time.Hour); err == nil {
		t.Fatal("expected error for truncated CSRF token")
	}
}
