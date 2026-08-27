package auth

import (
	"bytes"
	"testing"
)

// TestGenerateWebAuthnHandle_isSixtyFourRandomBytes pins both halves of the
// recommendation. The length is the specification's; the randomness is the point
// — a handle an authenticator may reveal without verifying the user must say
// nothing about the account, and a derived one says at least how many accounts
// exist and in what order.
func TestGenerateWebAuthnHandle_isSixtyFourRandomBytes(t *testing.T) {
	t.Parallel()

	first := GenerateWebAuthnHandle()
	if len(first) != WebAuthnHandleSize {
		t.Errorf("len(GenerateWebAuthnHandle()) = %d, want %d", len(first), WebAuthnHandleSize)
	}
	if WebAuthnHandleSize != 64 {
		t.Errorf("WebAuthnHandleSize = %d, want 64 (WebAuthn caps a user handle at 64 bytes)", WebAuthnHandleSize)
	}

	// Two handles colliding is a 2^-512 event, so equality means the value is
	// not random at all — a constant, or derived from something shared.
	second := GenerateWebAuthnHandle()
	if bytes.Equal(first, second) {
		t.Errorf("two calls returned the same handle %x, want independent random values", first)
	}
	if bytes.Equal(first, make([]byte, WebAuthnHandleSize)) {
		t.Errorf("GenerateWebAuthnHandle() = all zeroes, want random bytes")
	}
}
