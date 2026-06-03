package auth

import (
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
		plaintext, hash, err := GenerateOpaqueToken()
		if err != nil {
			t.Skipf("GenerateOpaqueToken error: %v", err)
		}

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
