package auth

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestRotateSessionToken(t *testing.T) {
	t.Parallel()
	oldPlain, oldHash, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	newPlain, newHash, gotOldHash, err := RotateSessionToken(oldPlain)
	if err != nil {
		t.Fatal(err)
	}
	if gotOldHash != oldHash {
		t.Errorf("RotateSessionToken() oldHash = %q, want %q", gotOldHash, oldHash)
	}
	if newPlain == oldPlain {
		t.Error("RotateSessionToken() new plaintext equals the old one, want a fresh token")
	}
	if newHash == oldHash {
		t.Error("RotateSessionToken() new hash equals the old one, want a fresh hash")
	}
	if got := SessionHash(newPlain); got != newHash {
		t.Errorf("SessionHash(new plaintext) = %q, want the returned new hash %q", got, newHash)
	}
}

func TestCSRFToken_RoundTrip(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sessHash := "abc123"
	token, err := CSRFToken(key, sessHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCSRFToken(key, sessHash, token, time.Hour); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestCSRFToken_WrongSession(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	token, _ := CSRFToken(key, "session1")
	if err := VerifyCSRFToken(key, "session2", token, time.Hour); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestCSRFToken_Expired(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	token, _ := CSRFToken(key, "sess")
	// Verify with 0 maxAge should expire immediately
	if err := VerifyCSRFToken(key, "sess", token, 0); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestCSRFToken_WrongKey(t *testing.T) {
	t.Parallel()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, _ = rand.Read(key1)
	_, _ = rand.Read(key2)
	token, _ := CSRFToken(key1, "sess")
	if err := VerifyCSRFToken(key2, "sess", token, time.Hour); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestCSRFToken_EmptyKey(t *testing.T) {
	t.Parallel()
	t.Run("nil key rejected", func(t *testing.T) {
		t.Parallel()
		if _, err := CSRFToken(nil, "sess"); err == nil {
			t.Error("CSRFToken(nil key) = nil error, want error")
		}
	})
	t.Run("empty key rejected", func(t *testing.T) {
		t.Parallel()
		if _, err := CSRFToken([]byte{}, "sess"); err == nil {
			t.Error("CSRFToken(empty key) = nil error, want error")
		}
	})
	t.Run("verify with nil key rejected", func(t *testing.T) {
		t.Parallel()
		if err := VerifyCSRFToken(nil, "sess", "anything", time.Hour); err != ErrTokenInvalid {
			t.Errorf("VerifyCSRFToken(nil key) = %v, want ErrTokenInvalid", err)
		}
	})
}

func TestCSRFToken_NegativeMaxAge_expired(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	token, err := CSRFToken(key, "sess")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCSRFToken(key, "sess", token, -time.Second); err != ErrTokenExpired {
		t.Fatalf("VerifyCSRFToken(maxAge=-1s) = %v, want ErrTokenExpired", err)
	}
}

func TestCSRFToken_BitFlip_rejected(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	token, err := CSRFToken(key, "sess")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	// Flipping any single bit of the token (nonce, expiry, or HMAC) must break
	// verification: the signature covers the whole payload.
	for i := range raw {
		tampered := make([]byte, len(raw))
		copy(tampered, raw)
		tampered[i] ^= 0x01
		encoded := base64.RawURLEncoding.EncodeToString(tampered)
		if err := VerifyCSRFToken(key, "sess", encoded, time.Hour); err == nil {
			t.Fatalf("VerifyCSRFToken accepted a token with a flipped bit at byte %d", i)
		}
	}
}

func TestGenerateOpaqueToken(t *testing.T) {
	t.Parallel()
	plain, hash, err := GenerateOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 64 { // 32 bytes hex-encoded
		t.Errorf("GenerateOpaqueToken() plaintext length = %d, want 64", len(plain))
	}
	if got := HexSHA256(plain); got != hash {
		t.Errorf("HexSHA256(plaintext) = %q, want the returned hash %q", got, hash)
	}
}

func TestVerifyOpaqueToken_Valid(t *testing.T) {
	t.Parallel()
	plain, hash, _ := GenerateOpaqueToken()
	expires := time.Now().Add(time.Hour)
	if err := VerifyOpaqueToken(plain, hash, expires); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestVerifyOpaqueToken_Expired(t *testing.T) {
	t.Parallel()
	plain, hash, _ := GenerateOpaqueToken()
	expires := time.Now().Add(-time.Hour)
	if err := VerifyOpaqueToken(plain, hash, expires); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyOpaqueToken_WrongToken(t *testing.T) {
	t.Parallel()
	_, hash, _ := GenerateOpaqueToken()
	expires := time.Now().Add(time.Hour)
	if err := VerifyOpaqueToken("wrong", hash, expires); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}
