package webauthn

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/cplieger/auth/v5"
	"github.com/go-webauthn/webauthn/protocol"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// FuzzFormatAAGUID pins two invariants of formatAAGUID: a 16-byte input always
// formats to a canonical lowercase UUID that parses back to the original bytes,
// and any other length yields the empty string.
func FuzzFormatAAGUID(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Add(make([]byte, 17))

	f.Fuzz(func(t *testing.T, input []byte) {
		result := formatAAGUID(input)

		if len(input) != 16 {
			if result != "" {
				t.Fatalf("formatAAGUID(%d-byte input) = %q, want empty string", len(input), result)
			}
			return
		}

		if !uuidRe.MatchString(result) {
			t.Fatalf("formatAAGUID(% x) = %q, want canonical UUID format", input, result)
		}
		if got := parseAAGUID(result); !bytes.Equal(got, input) {
			t.Fatalf("parseAAGUID(formatAAGUID(% x)) = % x, want round-trip to original", input, got)
		}
	})
}

// FuzzCredentialFromAPI exercises the credential-decoding path: it feeds
// arbitrary bytes into RawAttestation (json-unmarshalled inside the function) and
// asserts the decoder is total (never panics) and that attestation contents can
// never leak into the authenticator flags or identity fields. Complements the
// every-PR rapid round-trip property with a persistent coverage-guided corpus.
//
// The flags travel as the stored raw octet, so each decoded boolean is asserted
// against the specification's bit position for it. That pins the mapping itself:
// a swap between two flags would otherwise be invisible.
func FuzzCredentialFromAPI(f *testing.F) {
	f.Add([]byte(nil), "", uint32(0), uint8(0))
	f.Add([]byte("not valid json"), "usb", uint32(1), uint8(0xff))
	f.Add([]byte("{}"), "usb,nfc", uint32(42), uint8(0x15))
	f.Add([]byte(`{"clientDataJSON":"AQID"}`), "internal", uint32(7), uint8(0x0a))
	f.Add([]byte("{"), "a,,b", uint32(4294967295), uint8(0x1f))

	f.Fuzz(func(t *testing.T, raw []byte, transport string, signCount uint32, flagBits uint8) {
		cred := &auth.PasskeyCredential{
			CredentialID:   []byte{1, 2, 3},
			PublicKey:      []byte{4, 5, 6},
			AAGUID:         make([]byte, 16),
			Transport:      transport,
			SignCount:      signCount,
			RawAttestation: raw,
			RawFlags:       flagBits,
			CloneWarning:   flagBits&16 != 0,
		}

		got := credentialFromAPI(cred)

		if want := flagBits&uint8(protocol.FlagUserPresent) != 0; got.Flags.UserPresent != want {
			t.Errorf("UserPresent = %v, want %v (RawFlags %#08b)", got.Flags.UserPresent, want, flagBits)
		}
		if want := flagBits&uint8(protocol.FlagUserVerified) != 0; got.Flags.UserVerified != want {
			t.Errorf("UserVerified = %v, want %v (RawFlags %#08b)", got.Flags.UserVerified, want, flagBits)
		}
		if want := flagBits&uint8(protocol.FlagBackupEligible) != 0; got.Flags.BackupEligible != want {
			t.Errorf("BackupEligible = %v, want %v (RawFlags %#08b)", got.Flags.BackupEligible, want, flagBits)
		}
		if want := flagBits&uint8(protocol.FlagBackupState) != 0; got.Flags.BackupState != want {
			t.Errorf("BackupState = %v, want %v (RawFlags %#08b)", got.Flags.BackupState, want, flagBits)
		}
		if got.Authenticator.CloneWarning != cred.CloneWarning {
			t.Errorf("CloneWarning = %v, want %v", got.Authenticator.CloneWarning, cred.CloneWarning)
		}
		if !bytes.Equal(got.ID, cred.CredentialID) {
			t.Errorf("ID = %x, want %x", got.ID, cred.CredentialID)
		}
		if got.Authenticator.SignCount != signCount {
			t.Errorf("SignCount = %d, want %d", got.Authenticator.SignCount, signCount)
		}
	})
}
