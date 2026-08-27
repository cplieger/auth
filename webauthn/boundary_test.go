package webauthn

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cplieger/auth/v5"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// TestTranslateAssertionError_translatesRatherThanWraps is the test that keeps
// the boundary closed on the error path. Wrapping the upstream error would put a
// go-webauthn type in this package's reachable output, and a caller matching on
// it would then be coupled to a dependency this library exists to hide. So the
// assertion is deliberately negative: the upstream type must NOT be reachable.
func TestTranslateAssertionError_translatesRatherThanWraps(t *testing.T) {
	t.Parallel()
	upstream := &protocol.ErrorUnknownCredential{}

	got := translateAssertionError(upstream)

	if !errors.Is(got, ErrUnknownCredential) {
		t.Errorf("translateAssertionError(unknown credential) = %v, want it to match ErrUnknownCredential", got)
	}
	if _, ok := errors.AsType[*protocol.ErrorUnknownCredential](got); ok {
		t.Errorf("translateAssertionError(unknown credential) leaks the upstream error type through errors.As; want it translated, not wrapped")
	}
}

// TestTranslateAssertionError_keepsEveryOtherCause is the other half: only the
// unknown-credential case is translated, and a verification failure must stay
// diagnosable.
func TestTranslateAssertionError_keepsEveryOtherCause(t *testing.T) {
	t.Parallel()
	cause := errors.New("challenge mismatch")

	got := translateAssertionError(cause)

	if !errors.Is(got, cause) {
		t.Errorf("translateAssertionError(%v) = %v, want the cause to stay reachable", cause, got)
	}
	if errors.Is(got, ErrUnknownCredential) {
		t.Errorf("translateAssertionError(%v) = %v, want it NOT to match ErrUnknownCredential", cause, got)
	}
}

// TestTranslateAssertionError_findsTheCauseThroughAWrap pins that detection
// walks the chain, because upstream reports this condition from inside its own
// ceremony error rather than as the outermost value.
func TestTranslateAssertionError_findsTheCauseThroughAWrap(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("verifying assertion: %w", &protocol.ErrorUnknownCredential{})

	if got := translateAssertionError(wrapped); !errors.Is(got, ErrUnknownCredential) {
		t.Errorf("translateAssertionError(wrapped unknown credential) = %v, want it to match ErrUnknownCredential", got)
	}
}

// TestRegistrationRecord_recordsTheRelyingParty pins the field that makes a
// relying-party rename detectable. Without it a stored passkey cannot say which
// relying party it belongs to, and changing the RP ID silently orphans every one
// of them.
func TestRegistrationRecord_recordsTheRelyingParty(t *testing.T) {
	t.Parallel()
	rp := testRelyingParty(t)
	user := &User{AuthUser: &auth.User{ID: 99, Username: "alex"}}
	cred := &gowebauthn.Credential{ID: []byte{1, 2, 3}, PublicKey: []byte{4, 5}}

	got := registrationRecord(rp, user, cred)

	if got.RPID != "example.com" {
		t.Errorf("registrationRecord().RPID = %q, want %q", got.RPID, "example.com")
	}
	if got.UserID != 99 {
		t.Errorf("registrationRecord().UserID = %d, want 99", got.UserID)
	}
	if got.Name != "" {
		t.Errorf("registrationRecord().Name = %q, want empty (the caller derives it from existing names)", got.Name)
	}
}

// TestUserAdapter_satisfiesUpstreamWithoutExportingIt records the shape the
// boundary depends on: the exported User carries the three interface methods
// that return first-party types, and the unexported adapter carries the fourth.
// If WebAuthnCredentials were moved back onto User, this test would still pass —
// what it pins is that the adapter is the value the ceremony functions hand
// upstream, so the assertion in CompleteLogin keeps matching.
func TestUserAdapter_satisfiesUpstreamWithoutExportingIt(t *testing.T) {
	t.Parallel()
	user := &User{
		AuthUser: &auth.User{ID: 1, Username: "alex", DisplayName: "Alex"},
		Credentials: []auth.PasskeyCredential{
			{CredentialID: []byte{7}, Transport: "internal"},
		},
	}
	adapter := &userAdapter{User: user}

	if got := adapter.WebAuthnName(); got != "alex" {
		t.Errorf("adapter.WebAuthnName() = %q, want %q", got, "alex")
	}
	if got := adapter.WebAuthnDisplayName(); got != "Alex" {
		t.Errorf("adapter.WebAuthnDisplayName() = %q, want %q", got, "Alex")
	}
	creds := adapter.WebAuthnCredentials()
	if len(creds) != 1 {
		t.Fatalf("adapter.WebAuthnCredentials() len = %d, want 1", len(creds))
	}
	if creds[0].ID[0] != 7 {
		t.Errorf("adapter.WebAuthnCredentials()[0].ID = %v, want [7]", creds[0].ID)
	}
}
