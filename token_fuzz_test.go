package auth

import (
	"encoding/base64"
	"testing"
	"time"
)

func FuzzVerifyOpaqueToken(f *testing.F) {
	f.Add("random-plaintext")
	f.Add("")
	f.Add("\x00\x01\x02\x03")
	f.Add("正確なトークン")

	f.Fuzz(func(t *testing.T, fuzzInput string) {
		// Generate a real token via production code
		plaintext, hash := GenerateOpaqueToken()

		// Round-trip: correct plaintext must verify
		if err := VerifyOpaqueToken(plaintext, hash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}

		// Fuzzed input must not verify (unless it happens to equal plaintext)
		if fuzzInput == plaintext {
			return
		}
		if err := VerifyOpaqueToken(fuzzInput, hash, time.Now().Add(time.Hour)); err == nil {
			t.Fatal("fuzzed plaintext verified against hash")
		}
	})
}

// FuzzCSRFTokenRoundTrip is the persistent invariant net for the CSRF gate: a
// freshly generated token verifies against its own key and session, and never
// against a different session.
func FuzzCSRFTokenRoundTrip(f *testing.F) {
	f.Add([]byte("test-key-32-bytes-long-enough!!!"), "session-hash-value")
	f.Add([]byte("short"), "")
	f.Add([]byte("another-key-for-testing-purposes"), "different-session")

	f.Fuzz(func(t *testing.T, key []byte, sessHash string) {
		if len(key) == 0 {
			if _, err := CSRFToken(key, sessHash); err == nil {
				t.Error("CSRFToken(empty key) = nil error, want error")
			}
			return
		}
		tok, err := CSRFToken(key, sessHash)
		if err != nil {
			t.Skipf("CSRFToken error: %v", err)
		}
		if err := VerifyCSRFToken(key, sessHash, tok, time.Hour); err != nil {
			t.Errorf("generated token failed to verify: %v", err)
		}
		if sessHash != "other" {
			if err := VerifyCSRFToken(key, "other", tok, time.Hour); err == nil {
				t.Error("token verified for a different session")
			}
		}
	})
}

// FuzzVerifyCSRFToken drives arbitrary, attacker-shaped input through the CSRF
// verifier. Beyond not panicking, it pins two security invariants: an empty key
// can never authorize a token, and a token that does not decode to the exact
// wire length is always rejected as invalid (never accepted, never reported as
// a mere expiry).
func FuzzVerifyCSRFToken(f *testing.F) {
	f.Add([]byte("key"), "session", "dGVzdHRva2Vu", int64(3600))
	f.Add([]byte(""), "", "", int64(0))
	f.Add([]byte("k"), "s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", int64(-1))
	f.Add([]byte("longkey1234567890"), "hash", "////", int64(1))

	f.Fuzz(func(t *testing.T, key []byte, sessHash, token string, maxAgeSec int64) {
		maxAge := time.Duration(maxAgeSec) * time.Second
		err := VerifyCSRFToken(key, sessHash, token, maxAge)

		if len(key) == 0 {
			if err != ErrTokenInvalid {
				t.Errorf("VerifyCSRFToken(empty key) = %v, want ErrTokenInvalid", err)
			}
			return
		}
		raw, decErr := base64.RawURLEncoding.DecodeString(token)
		if decErr != nil || len(raw) != csrfTokenLen {
			if err != ErrTokenInvalid {
				t.Errorf("VerifyCSRFToken(malformed token) = %v, want ErrTokenInvalid", err)
			}
		}
	})
}
