package webauthn

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/cplieger/auth"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// parseAAGUID parses a UUID string into 16 bytes.
func parseAAGUID(s string) []byte {
	clean := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return nil
	}
	return b
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
	u := &User{AuthUser: &auth.User{ID: 42, Username: "alice", DisplayName: "Alice Smith"}}
	if u.WebAuthnName() != "alice" {
		t.Errorf("WebAuthnName() = %q", u.WebAuthnName())
	}
	if u.WebAuthnDisplayName() != "Alice Smith" {
		t.Errorf("WebAuthnDisplayName() = %q", u.WebAuthnDisplayName())
	}
}

func TestWebAuthnUser_WebAuthnID_encodes_varint(t *testing.T) {
	t.Parallel()
	u := &User{AuthUser: &auth.User{ID: 42}}
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
			cred := &auth.PasskeyCredential{
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
			waCred := &gowebauthn.Credential{
				ID: []byte{10, 20}, PublicKey: []byte{30, 40},
				Transport: tt.transports,
				Flags:     gowebauthn.CredentialFlags{UserPresent: true},
				Authenticator: gowebauthn.Authenticator{
					AAGUID: make([]byte, 16), SignCount: 99,
				},
			}
			got := CredentialToAPI(waCred, 7, "test-key")
			if got.Transport != tt.wantTransport {
				t.Errorf("Transport = %q, want %q", got.Transport, tt.wantTransport)
			}
		})
	}
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

func TestAPICredentialToWebAuthn_corrupted_attestation(t *testing.T) {
	t.Parallel()
	cred := &auth.PasskeyCredential{
		CredentialID:   []byte{1},
		PublicKey:      []byte{2},
		AAGUID:         make([]byte, 16),
		RawAttestation: []byte("not valid json"),
	}
	got := APICredentialToWebAuthn(cred)
	if !bytes.Equal(got.ID, []byte{1}) {
		t.Errorf("CredentialID mismatch after corrupted attestation")
	}
}

func TestCloneWarning_roundtrip(t *testing.T) {
	t.Parallel()
	cred := &auth.PasskeyCredential{
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
	back := CredentialToAPI(&waCred, 1, "test")
	if !back.CloneWarning {
		t.Error("CredentialToAPI did not propagate CloneWarning")
	}
}

func TestNewWebAuthn_valid_config(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn error: %v", err)
	}
	if wa == nil {
		t.Fatal("NewWebAuthn returned nil")
	}
}

func TestBeginRegistration_with_user(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	user := &User{AuthUser: &auth.User{ID: 1, Username: "test"}}
	creation, session, err := BeginRegistration(wa, user)
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}
	if creation == nil {
		t.Fatal("creation nil")
	}
	if session == nil {
		t.Fatal("session nil")
	}
}

func TestBeginRegistration_requires_user_verification(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	user := &User{AuthUser: &auth.User{ID: 1, Username: "test"}}
	creation, _, err := BeginRegistration(wa, user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	uv := creation.Response.AuthenticatorSelection.UserVerification
	if uv != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want %q", uv, protocol.VerificationRequired)
	}
}

func TestBeginLogin_requires_user_verification(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}
	assertion, _, err := BeginLogin(wa)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	uv := assertion.Response.UserVerification
	if uv != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want %q", uv, protocol.VerificationRequired)
	}
}

// CredentialToAPI populates RawAttestation only when the source credential
// carries attestation data: an attestation with either an Object or a
// ClientDataJSON present is marshalled, while a fully-empty attestation leaves
// RawAttestation nil.
func TestCredentialToAPI_RawAttestation_presence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		object         []byte
		clientDataJSON []byte
		wantNil        bool
	}{
		{"both_empty_omits_attestation", nil, nil, true},
		{"object_only_marshals", []byte{0xa0, 0x01}, nil, false},
		{"clientdata_only_marshals", nil, []byte(`{"x":1}`), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			waCred := &gowebauthn.Credential{
				ID:            []byte{1, 2, 3},
				PublicKey:     []byte{4, 5, 6},
				Authenticator: gowebauthn.Authenticator{AAGUID: make([]byte, 16)},
			}
			waCred.Attestation.Object = tt.object
			waCred.Attestation.ClientDataJSON = tt.clientDataJSON

			got := CredentialToAPI(waCred, 7, "key")

			if tt.wantNil && got.RawAttestation != nil {
				t.Errorf("CredentialToAPI(Object=%v, ClientDataJSON=%v).RawAttestation = %v, want nil",
					tt.object, tt.clientDataJSON, got.RawAttestation)
			}
			if !tt.wantNil && got.RawAttestation == nil {
				t.Errorf("CredentialToAPI(Object=%v, ClientDataJSON=%v).RawAttestation = nil, want non-nil",
					tt.object, tt.clientDataJSON)
			}
		})
	}
}

// APICredentialToWebAuthn restores a non-empty RawAttestation back into the
// credential's Attestation object byte-for-byte (the inverse of CredentialToAPI).
func TestAPICredentialToWebAuthn_restores_attestation_from_raw(t *testing.T) {
	t.Parallel()

	src := &gowebauthn.Credential{ID: []byte{9}, PublicKey: []byte{8}}
	src.Attestation.Object = []byte{0xa0, 0x01, 0x02}
	apiCred := CredentialToAPI(src, 1, "key")
	if len(apiCred.RawAttestation) == 0 {
		t.Fatal("setup: expected non-empty RawAttestation from CredentialToAPI")
	}

	got := APICredentialToWebAuthn(apiCred)

	if !bytes.Equal(got.Attestation.Object, []byte{0xa0, 0x01, 0x02}) {
		t.Errorf("APICredentialToWebAuthn restored Attestation.Object = %v, want %v",
			got.Attestation.Object, []byte{0xa0, 0x01, 0x02})
	}
}

// recordingHandler captures every slog.Record regardless of level.
type recordingHandler struct {
	records []slog.Record
	mu      sync.Mutex
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) countMsg(sub string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if bytes.Contains([]byte(r.Message), []byte(sub)) {
			n++
		}
	}
	return n
}

// withCapturedDefaultLogger temporarily swaps slog's default logger for a
// capturing handler and restores it on cleanup. APICredentialToWebAuthn logs
// via the package-global slog, so these tests cannot run in parallel.
func withCapturedDefaultLogger(t *testing.T) *recordingHandler {
	t.Helper()
	h := &recordingHandler{}
	orig := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(orig) })
	return h
}

// An empty RawAttestation is skipped silently: APICredentialToWebAuthn logs no
// corrupted-attestation warning when there is nothing to unmarshal.
func TestAPICredentialToWebAuthn_empty_raw_attestation_no_warning(t *testing.T) {
	h := withCapturedDefaultLogger(t)

	cred := &auth.PasskeyCredential{
		CredentialID: []byte{1},
		PublicKey:    []byte{2},
		AAGUID:       make([]byte, 16),
	}

	_ = APICredentialToWebAuthn(cred)

	if n := h.countMsg("corrupted attestation"); n != 0 {
		t.Errorf("APICredentialToWebAuthn(empty RawAttestation) logged %d corrupted-attestation warnings, want 0", n)
	}
}

// A non-empty but malformed RawAttestation is reported once as a
// corrupted-attestation warning and otherwise ignored.
func TestAPICredentialToWebAuthn_invalid_raw_attestation_warns(t *testing.T) {
	h := withCapturedDefaultLogger(t)

	cred := &auth.PasskeyCredential{
		CredentialID:   []byte{1},
		PublicKey:      []byte{2},
		AAGUID:         make([]byte, 16),
		RawAttestation: []byte("not valid json"),
	}

	_ = APICredentialToWebAuthn(cred)

	if n := h.countMsg("corrupted attestation"); n != 1 {
		t.Errorf("APICredentialToWebAuthn(invalid RawAttestation) logged %d corrupted-attestation warnings, want 1", n)
	}
}
