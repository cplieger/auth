package auth

import "testing"

func TestNewAPIKeyVerifier_ignoresNilOption(t *testing.T) {
	t.Parallel()
	// A nil entry in the variadic options list must be skipped, never invoked.
	// The constructor guards each option with a non-nil check; without that
	// guard a nil option would be called as a function and panic. Passing an
	// explicit nil option must still yield a usable verifier.
	v := NewAPIKeyVerifier(newFakeSessionStore(), nil)
	if v == nil {
		t.Fatal("NewAPIKeyVerifier(store, nil) = nil, want a usable verifier (nil option must be skipped)")
	}
}
