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

// TestLegacyWebAuthnHandle_isStableAndIDSpecific is what makes the backfill safe:
// the value it writes must be exactly what the old derivation produced, or every
// passkey registered under that scheme stops resolving.
func TestLegacyWebAuthnHandle_isStableAndIDSpecific(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   int64
	}{
		{name: "first account", id: 1},
		{name: "later account", id: 7},
		{name: "large id", id: 1 << 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := LegacyWebAuthnHandle(tt.id)
			if len(got) == 0 {
				t.Fatalf("LegacyWebAuthnHandle(%d) is empty; a user handle must not be empty", tt.id)
			}
			if again := LegacyWebAuthnHandle(tt.id); !bytes.Equal(got, again) {
				t.Errorf("LegacyWebAuthnHandle(%d) = %x then %x, want a stable value", tt.id, got, again)
			}
			if other := LegacyWebAuthnHandle(tt.id + 1); bytes.Equal(got, other) {
				t.Errorf("LegacyWebAuthnHandle(%d) and (%d) both = %x, want different accounts to differ", tt.id, tt.id+1, got)
			}
		})
	}
}

// TestLegacyWebAuthnHandle_isNotTheGeneratedShape records the difference that
// makes the migration worth doing: the derived handle is short and ordered, the
// generated one is neither.
func TestLegacyWebAuthnHandle_isNotTheGeneratedShape(t *testing.T) {
	t.Parallel()
	if got := len(LegacyWebAuthnHandle(7)); got >= WebAuthnHandleSize {
		t.Errorf("len(LegacyWebAuthnHandle(7)) = %d, want well under %d — the derived handle is a varint, not a random block", got, WebAuthnHandleSize)
	}
}
