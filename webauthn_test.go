package auth

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"pgregory.net/rapid"
)

func TestProperty_WebAuthnCredentialStorageRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		db := newFakeSessionStore()
		ctx := context.Background()

		user := &User{Username: "webauthn-user", PasswordHash: "dummy", Role: "admin", Enabled: true}
		if err := db.CreateUser(ctx, user); err != nil {
			rt.Fatalf("CreateUser: %v", err)
		}

		credID := rapid.SliceOfN(rapid.Byte(), 16, 64).Draw(rt, "credentialID")
		pubKey := rapid.SliceOfN(rapid.Byte(), 32, 128).Draw(rt, "publicKey")
		signCount := rapid.Uint32().Draw(rt, "signCount")
		name := rapid.StringN(1, 50, -1).Draw(rt, "name")
		aaguid := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(rt, "aaguid")
		transport := rapid.SampledFrom([]string{"", "usb", "nfc", "ble", "internal", "usb,nfc"}).Draw(rt, "transport")
		backupEligible := rapid.Bool().Draw(rt, "backupEligible")
		backupState := rapid.Bool().Draw(rt, "backupState")
		userPresent := rapid.Bool().Draw(rt, "userPresent")
		userVerified := rapid.Bool().Draw(rt, "userVerified")

		cred := &PasskeyCredential{
			UserID: user.ID, CredentialID: credID, PublicKey: pubKey,
			AAGUID: aaguid, AttestationType: "none", Transport: transport,
			SignCount: signCount, Name: name,
			BackupEligible: backupEligible, BackupState: backupState,
			UserPresent: userPresent, UserVerified: userVerified,
		}

		if err := db.CreatePasskey(ctx, cred); err != nil {
			rt.Fatalf("CreatePasskey: %v", err)
		}

		got, err := db.GetPasskeyByCredentialID(ctx, credID)
		if err != nil {
			rt.Fatalf("GetPasskeyByCredentialID: %v", err)
		}
		if got == nil {
			rt.Fatal("got nil")
			return
		}
		if !bytes.Equal(got.CredentialID, credID) {
			rt.Fatal("CredentialID mismatch")
		}
		if got.SignCount != signCount {
			rt.Fatalf("SignCount: got %d, want %d", got.SignCount, signCount)
		}
		if got.BackupEligible != backupEligible {
			rt.Fatalf("BackupEligible: got %v, want %v", got.BackupEligible, backupEligible)
		}
		if got.BackupState != backupState {
			rt.Fatalf("BackupState: got %v, want %v", got.BackupState, backupState)
		}
		if got.UserPresent != userPresent {
			rt.Fatalf("UserPresent: got %v, want %v", got.UserPresent, userPresent)
		}
		if got.UserVerified != userVerified {
			rt.Fatalf("UserVerified: got %v, want %v", got.UserVerified, userVerified)
		}
	})
}

func TestPasskeyFriendlyName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		aaguid   string
		want     string
		existing []string
	}{
		{"known", "adce0002-35bc-c60a-648b-0b25f1f05503", "Chrome on Mac", nil},
		{"unknown", "ffffffff-ffff-ffff-ffff-ffffffffffff", "Passkey 1", nil},
		{"dup second", "adce0002-35bc-c60a-648b-0b25f1f05503", "Chrome on Mac 2", []string{"Chrome on Mac"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			aaguid := parseAAGUID(tc.aaguid)
			got := PasskeyFriendlyName(aaguid, tc.existing)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWebAuthnUser_interface_methods(t *testing.T) {
	t.Parallel()
	u := &WebAuthnUser{User: &User{ID: 42, Username: "alice", DisplayName: "Alice Smith"}}
	if u.WebAuthnName() != "alice" {
		t.Errorf("WebAuthnName() = %q", u.WebAuthnName())
	}
	if u.WebAuthnDisplayName() != "Alice Smith" {
		t.Errorf("WebAuthnDisplayName() = %q", u.WebAuthnDisplayName())
	}
}

func TestWebAuthnUser_WebAuthnID_encodes_varint(t *testing.T) {
	t.Parallel()
	u := &WebAuthnUser{User: &User{ID: 42}}
	got := u.WebAuthnID()
	decoded, n := binary.Varint(got)
	if n <= 0 {
		t.Fatal("Varint failed")
	}
	if decoded != 42 {
		t.Errorf("got %d, want 42", decoded)
	}
}

func TestAPICredentialToWebAuthn_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		transport      string
		wantTransports int
	}{
		{"no_transport", "", 0},
		{"single", "internal", 1},
		{"multi", "usb,nfc,ble", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cred := &PasskeyCredential{
				CredentialID: []byte{1, 2, 3}, PublicKey: []byte{4, 5, 6},
				AAGUID: make([]byte, 16), AttestationType: "none",
				Transport: tt.transport, SignCount: 42,
				BackupEligible: true, UserPresent: true, UserVerified: true,
			}
			got := APICredentialToWebAuthn(cred)
			if len(got.Transport) != tt.wantTransports {
				t.Errorf("transport count = %d, want %d", len(got.Transport), tt.wantTransports)
			}
			if !got.Flags.UserPresent {
				t.Error("UserPresent = false, want true")
			}
			if !got.Flags.UserVerified {
				t.Error("UserVerified = false, want true")
			}
			if !got.Flags.BackupEligible {
				t.Error("BackupEligible = false, want true")
			}
			if got.Flags.BackupState {
				t.Error("BackupState = true, want false")
			}
		})
	}
}

func TestWebAuthnCredentialToAPI_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		wantTransport string
		transports    []protocol.AuthenticatorTransport
	}{
		{"no_transports", "", nil},
		{"single", "internal", []protocol.AuthenticatorTransport{"internal"}},
		{"multi", "usb,nfc", []protocol.AuthenticatorTransport{"usb", "nfc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			waCred := &webauthn.Credential{
				ID: []byte{10, 20}, PublicKey: []byte{30, 40},
				Transport: tt.transports,
				Flags:     webauthn.CredentialFlags{UserPresent: true},
				Authenticator: webauthn.Authenticator{
					AAGUID: make([]byte, 16), SignCount: 99,
				},
			}
			got := WebAuthnCredentialToAPI(waCred, 7, "test-key")
			if got.Transport != tt.wantTransport {
				t.Errorf("Transport = %q, want %q", got.Transport, tt.wantTransport)
			}
		})
	}
}

func TestProperty_CredentialConversionRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		credID := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "credentialID")
		pubKey := rapid.SliceOfN(rapid.Byte(), 1, 128).Draw(rt, "publicKey")
		aaguid := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(rt, "aaguid")
		signCount := rapid.Uint32().Draw(rt, "signCount")
		transport := rapid.SampledFrom([]string{"", "usb", "nfc", "ble", "internal", "usb,nfc"}).Draw(rt, "transport")
		backupEligible := rapid.Bool().Draw(rt, "backupEligible")
		backupState := rapid.Bool().Draw(rt, "backupState")
		userPresent := rapid.Bool().Draw(rt, "userPresent")
		userVerified := rapid.Bool().Draw(rt, "userVerified")
		name := rapid.StringN(1, 50, -1).Draw(rt, "name")
		userID := rapid.Int64Range(1, 1000).Draw(rt, "userID")

		original := &PasskeyCredential{
			UserID: userID, CredentialID: credID, PublicKey: pubKey,
			AAGUID: aaguid, AttestationType: "none", Transport: transport,
			SignCount: signCount, Name: name,
			BackupEligible: backupEligible, BackupState: backupState,
			UserPresent: userPresent, UserVerified: userVerified,
		}

		waCred := APICredentialToWebAuthn(original)
		roundTripped := WebAuthnCredentialToAPI(&waCred, userID, name)

		if !bytes.Equal(roundTripped.CredentialID, original.CredentialID) {
			rt.Fatal("CredentialID mismatch")
		}
		if roundTripped.SignCount != original.SignCount {
			rt.Fatalf("SignCount: got %d, want %d", roundTripped.SignCount, original.SignCount)
		}
		if roundTripped.Transport != original.Transport {
			rt.Fatalf("Transport: got %q, want %q", roundTripped.Transport, original.Transport)
		}
		if roundTripped.BackupEligible != original.BackupEligible {
			rt.Fatalf("BackupEligible: got %v, want %v", roundTripped.BackupEligible, original.BackupEligible)
		}
		if roundTripped.BackupState != original.BackupState {
			rt.Fatalf("BackupState: got %v, want %v", roundTripped.BackupState, original.BackupState)
		}
		if roundTripped.UserPresent != original.UserPresent {
			rt.Fatalf("UserPresent: got %v, want %v", roundTripped.UserPresent, original.UserPresent)
		}
		if roundTripped.UserVerified != original.UserVerified {
			rt.Fatalf("UserVerified: got %v, want %v", roundTripped.UserVerified, original.UserVerified)
		}
	})
}

func TestFormatAAGUID_edge_cases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		want  string
		input []byte
	}{
		{"nil", "", nil},
		{"empty", "", []byte{}},
		{"too_short", "", []byte{0x01, 0x02}},
		{"too_long", "", make([]byte, 17)},
		{"valid_zeros", "00000000-0000-0000-0000-000000000000", make([]byte, 16)},
		{"valid_known", "adce0002-35bc-c60a-648b-0b25f1f05503", parseAAGUID("adce0002-35bc-c60a-648b-0b25f1f05503")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := formatAAGUID(tt.input)
			if got != tt.want {
				t.Errorf("formatAAGUID(%x) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseAAGUID_edge_cases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantNil bool
	}{
		{"valid", "adce0002-35bc-c60a-648b-0b25f1f05503", false},
		{"all_zeros", "00000000-0000-0000-0000-000000000000", false},
		{"invalid_hex", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", true},
		{"too_short", "adce0002-35bc", true},
		{"empty", "", true},
		{"no_dashes", "adce000235bcc60a648b0b25f1f05503", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseAAGUID(tt.input)
			if tt.wantNil && got != nil {
				t.Errorf("parseAAGUID(%q) = %x, want nil", tt.input, got)
			}
			if !tt.wantNil && got == nil {
				t.Errorf("parseAAGUID(%q) = nil, want non-nil", tt.input)
			}
		})
	}
}

func TestAPICredentialToWebAuthn_corrupted_attestation(t *testing.T) {
	t.Parallel()
	cred := &PasskeyCredential{
		CredentialID:   []byte{1},
		PublicKey:      []byte{2},
		AAGUID:         make([]byte, 16),
		RawAttestation: []byte("not valid json"),
	}
	// Should not panic; corrupted attestation is non-fatal.
	got := APICredentialToWebAuthn(cred)
	if !bytes.Equal(got.ID, []byte{1}) {
		t.Errorf("CredentialID mismatch after corrupted attestation")
	}
}

func TestWebAuthnCredentialToAPI_with_attestation(t *testing.T) {
	t.Parallel()
	waCred := &webauthn.Credential{
		ID:        []byte{1, 2, 3},
		PublicKey: []byte{4, 5, 6},
		Transport: []protocol.AuthenticatorTransport{"internal"},
		Flags: webauthn.CredentialFlags{
			UserPresent:  true,
			UserVerified: true,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    make([]byte, 16),
			SignCount: 10,
		},
		Attestation: webauthn.CredentialAttestation{
			Object:         []byte(`{"fmt":"none","attStmt":{}}`),
			ClientDataJSON: []byte(`{"type":"webauthn.create"}`),
		},
	}
	got := WebAuthnCredentialToAPI(waCred, 5, "attested-key")
	if got.RawAttestation == nil {
		t.Fatal("RawAttestation = nil, want non-nil when attestation data present")
	}
	if got.UserID != 5 {
		t.Errorf("UserID = %d, want 5", got.UserID)
	}
	if got.Name != "attested-key" {
		t.Errorf("Name = %q, want %q", got.Name, "attested-key")
	}
	if got.Transport != "internal" {
		t.Errorf("Transport = %q, want %q", got.Transport, "internal")
	}
}

func TestCloneWarning_roundtrip(t *testing.T) {
	t.Parallel()
	cred := &PasskeyCredential{
		CredentialID: []byte{1, 2, 3},
		PublicKey:    []byte{4, 5, 6},
		AAGUID:       make([]byte, 16),
		SignCount:    10,
		CloneWarning: true,
	}
	waCred := APICredentialToWebAuthn(cred)
	if !waCred.Authenticator.CloneWarning {
		t.Error("APICredentialToWebAuthn did not propagate CloneWarning")
	}

	back := WebAuthnCredentialToAPI(&waCred, 1, "test")
	if !back.CloneWarning {
		t.Error("WebAuthnCredentialToAPI did not propagate CloneWarning")
	}
}
