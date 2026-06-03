package auth

import (
	"testing"
	"time"
)

func FuzzVerifyCSRFToken(f *testing.F) {
	f.Add([]byte("key"), "session", "dGVzdHRva2Vu", int64(3600))
	f.Add([]byte(""), "", "", int64(0))
	f.Add([]byte("k"), "s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", int64(-1))
	f.Add([]byte("longkey1234567890"), "hash", "////", int64(1))

	f.Fuzz(func(t *testing.T, key []byte, sessHash, token string, maxAgeSec int64) {
		maxAge := time.Duration(maxAgeSec) * time.Second
		// Must not panic regardless of input
		_ = VerifyCSRFToken(key, sessHash, token, maxAge)
	})
}

func FuzzParsePHC(f *testing.F) {
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$c29tZWhhc2g")
	f.Add("")
	f.Add("$argon2id$v=19$m=0,t=0,p=0$$")
	f.Add("$argon2id$v=19$m=4294967295,t=4294967295,p=255$AAAA$BBBB")
	f.Add("$bcrypt$invalid$format$$$")
	f.Add("not-a-hash")
	f.Add("$argon2id$v=99$m=19456,t=2,p=1$AAAA$BBBB")
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$" + "A" + "$" + "B")

	f.Fuzz(func(t *testing.T, encoded string) {
		p, err := parsePHC(encoded)
		if err != nil {
			return
		}
		if p.iterations < 1 {
			t.Fatal("parsePHC succeeded but iterations < 1")
		}
		if p.parallelism < 1 {
			t.Fatal("parsePHC succeeded but parallelism < 1")
		}
		if p.keyLen < 1 {
			t.Fatal("parsePHC succeeded but keyLen < 1")
		}
	})
}

func FuzzCSRFTokenRoundTrip(f *testing.F) {
	f.Add([]byte("test-key-32-bytes-long-enough!!!"), "session-hash-value")
	f.Add([]byte("short"), "")
	f.Add([]byte("another-key-for-testing-purposes"), "different-session")

	f.Fuzz(func(t *testing.T, key []byte, sessHash string) {
		if len(key) == 0 {
			// Empty key should error
			_, err := CSRFToken(key, sessHash)
			if err == nil {
				t.Error("expected error for empty key")
			}
			return
		}
		tok, err := CSRFToken(key, sessHash)
		if err != nil {
			t.Skipf("CSRFToken error: %v", err)
		}
		// Token should verify against same key and session
		if err := VerifyCSRFToken(key, sessHash, tok, time.Hour); err != nil {
			t.Errorf("generated token should verify: %v", err)
		}
		// Token should NOT verify against different session
		if sessHash != "other" {
			if err := VerifyCSRFToken(key, "other", tok, time.Hour); err == nil {
				t.Error("token should not verify for different session")
			}
		}
	})
}
