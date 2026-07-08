package webauthn

import (
	"bytes"
	"testing"

	"github.com/cplieger/auth/v2"
	"pgregory.net/rapid"
)

// TestAPICredentialRoundTrip_preserves_fields asserts that converting a
// PasskeyCredential to a webauthn.Credential and back preserves every scalar
// field and all five authenticator flags. BackupEligible, BackupState, and
// UserVerified drive credential-trust decisions, so a conversion that silently
// dropped or swapped a flag would weaken authentication while the existing
// spot-check tests (which assert only UserPresent and CloneWarning) stayed green.
func TestAPICredentialRoundTrip_preserves_fields(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		orig := &auth.PasskeyCredential{
			CredentialID:    rapid.SliceOf(rapid.Byte()).Draw(t, "credID"),
			PublicKey:       rapid.SliceOf(rapid.Byte()).Draw(t, "pubKey"),
			AAGUID:          rapid.SliceOf(rapid.Byte()).Draw(t, "aaguid"),
			AttestationType: rapid.String().Draw(t, "attestationType"),
			Transport:       rapid.String().Draw(t, "transport"),
			SignCount:       rapid.Uint32().Draw(t, "signCount"),
			BackupEligible:  rapid.Bool().Draw(t, "backupEligible"),
			BackupState:     rapid.Bool().Draw(t, "backupState"),
			UserPresent:     rapid.Bool().Draw(t, "userPresent"),
			UserVerified:    rapid.Bool().Draw(t, "userVerified"),
			CloneWarning:    rapid.Bool().Draw(t, "cloneWarning"),
		}

		wa := APICredentialToWebAuthn(orig)
		got := CredentialToAPI(&wa, orig.UserID, orig.Name)

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
		if got.Transport != orig.Transport {
			t.Errorf("Transport = %q, want %q", got.Transport, orig.Transport)
		}
		if got.SignCount != orig.SignCount {
			t.Errorf("SignCount = %d, want %d", got.SignCount, orig.SignCount)
		}
		if got.BackupEligible != orig.BackupEligible {
			t.Errorf("BackupEligible = %v, want %v", got.BackupEligible, orig.BackupEligible)
		}
		if got.BackupState != orig.BackupState {
			t.Errorf("BackupState = %v, want %v", got.BackupState, orig.BackupState)
		}
		if got.UserPresent != orig.UserPresent {
			t.Errorf("UserPresent = %v, want %v", got.UserPresent, orig.UserPresent)
		}
		if got.UserVerified != orig.UserVerified {
			t.Errorf("UserVerified = %v, want %v", got.UserVerified, orig.UserVerified)
		}
		if got.CloneWarning != orig.CloneWarning {
			t.Errorf("CloneWarning = %v, want %v", got.CloneWarning, orig.CloneWarning)
		}
	})
}
