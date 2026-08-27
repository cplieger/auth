package webauthn

import (
	"bytes"
	"testing"

	"github.com/cplieger/auth/v5"
	"pgregory.net/rapid"
)

// TestAPICredentialRoundTrip_preserves_fields asserts that converting a
// PasskeyCredential to a gowebauthn.Credential and back preserves every scalar
// field of the credential record. BackupEligible, BackupState and UserVerified
// drive credential-trust decisions, so a conversion that silently dropped or
// swapped one would weaken authentication while the spot-check tests (which
// assert only UserPresent and CloneWarning) stayed green.
//
// The flags travel as the raw octet, which is authoritative, so the four
// booleans are asserted against what that octet implies rather than against
// what was drawn.
func TestAPICredentialRoundTrip_preserves_fields(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		discoverable := rapid.Bool().Draw(t, "discoverable")
		orig := &auth.PasskeyCredential{
			CredentialID:      rapid.SliceOf(rapid.Byte()).Draw(t, "credID"),
			PublicKey:         rapid.SliceOf(rapid.Byte()).Draw(t, "pubKey"),
			AAGUID:            rapid.SliceOf(rapid.Byte()).Draw(t, "aaguid"),
			AttestationType:   rapid.String().Draw(t, "attestationType"),
			AttestationFormat: rapid.String().Draw(t, "attestationFormat"),
			Attachment:        auth.AuthenticatorAttachment(rapid.String().Draw(t, "attachment")),
			Transport:         rapid.String().Draw(t, "transport"),
			SignCount:         rapid.Uint32().Draw(t, "signCount"),
			RawFlags:          rapid.Uint8Range(1, 255).Draw(t, "rawFlags"),
			CloneWarning:      rapid.Bool().Draw(t, "cloneWarning"),
			Discoverable:      &discoverable,
		}

		wa := credentialFromAPI(orig)
		got := credentialToAPI(&wa, orig.UserID, orig.Name)

		if !bytes.Equal(got.CredentialID, orig.CredentialID) {
			t.Errorf("CredentialID = %x, want %x", got.CredentialID, orig.CredentialID)
		}
		if !bytes.Equal(got.PublicKey, orig.PublicKey) {
			t.Errorf("PublicKey = %x, want %x", got.PublicKey, orig.PublicKey)
		}
		if !bytes.Equal(got.AAGUID, orig.AAGUID) {
			t.Errorf("AAGUID = %x, want %x", got.AAGUID, orig.AAGUID)
		}
		if got.AttestationType != orig.AttestationType {
			t.Errorf("AttestationType = %q, want %q", got.AttestationType, orig.AttestationType)
		}
		if got.AttestationFormat != orig.AttestationFormat {
			t.Errorf("AttestationFormat = %q, want %q", got.AttestationFormat, orig.AttestationFormat)
		}
		if got.Attachment != orig.Attachment {
			t.Errorf("Attachment = %q, want %q", got.Attachment, orig.Attachment)
		}
		if got.Transport != orig.Transport {
			t.Errorf("Transport = %q, want %q", got.Transport, orig.Transport)
		}
		if got.SignCount != orig.SignCount {
			t.Errorf("SignCount = %d, want %d", got.SignCount, orig.SignCount)
		}
		if got.RawFlags != orig.RawFlags {
			t.Errorf("RawFlags = %#08b, want %#08b", got.RawFlags, orig.RawFlags)
		}
		if got.CloneWarning != orig.CloneWarning {
			t.Errorf("CloneWarning = %v, want %v", got.CloneWarning, orig.CloneWarning)
		}
		if got.Discoverable == nil || *got.Discoverable != discoverable {
			t.Errorf("Discoverable = %v, want %v", got.Discoverable, discoverable)
		}

		// The four booleans are the bits of the octet that travelled.
		flags := wa.Flags
		if got.UserPresent != flags.UserPresent {
			t.Errorf("UserPresent = %v, want %v (RawFlags %#08b)", got.UserPresent, flags.UserPresent, orig.RawFlags)
		}
		if got.UserVerified != flags.UserVerified {
			t.Errorf("UserVerified = %v, want %v (RawFlags %#08b)", got.UserVerified, flags.UserVerified, orig.RawFlags)
		}
		if got.BackupEligible != flags.BackupEligible {
			t.Errorf("BackupEligible = %v, want %v (RawFlags %#08b)", got.BackupEligible, flags.BackupEligible, orig.RawFlags)
		}
		if got.BackupState != flags.BackupState {
			t.Errorf("BackupState = %v, want %v (RawFlags %#08b)", got.BackupState, flags.BackupState, orig.RawFlags)
		}
	})
}
