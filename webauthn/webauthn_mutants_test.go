package webauthn

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/cplieger/auth"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// These tests target boundary/negation mutants in the attestation
// (de)serialization paths of APICredentialToWebAuthn (L175/L176) and
// CredentialToAPI (L194).

// --- CredentialToAPI L194:
//
//	if len(c.Attestation.Object) > 0 || len(c.Attestation.ClientDataJSON) > 0 ---
//
// Covers both boundary mutants (> 0 → >= 0, which would always marshal) via the
// both-empty case, and both negation mutants (> 0 → <= 0) via the
// single-field-set cases.
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

			// given a webauthn credential with the specified attestation fields
			waCred := &gowebauthn.Credential{
				ID:            []byte{1, 2, 3},
				PublicKey:     []byte{4, 5, 6},
				Authenticator: gowebauthn.Authenticator{AAGUID: make([]byte, 16)},
			}
			waCred.Attestation.Object = tt.object
			waCred.Attestation.ClientDataJSON = tt.clientDataJSON

			// when converting to the API credential
			got := CredentialToAPI(waCred, 7, "key")

			// then RawAttestation is populated only when at least one field is set
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

// --- APICredentialToWebAuthn L175 negation: if len(c.RawAttestation) > 0 ---
//
// With a non-empty, valid RawAttestation the attestation must be unmarshalled
// back into the credential. The negation mutant (> 0 → <= 0) would skip the
// unmarshal, leaving Attestation.Object empty.
func TestAPICredentialToWebAuthn_restores_attestation_from_raw(t *testing.T) {
	t.Parallel()

	// given a credential whose RawAttestation was produced from a real
	// attestation object
	src := &gowebauthn.Credential{ID: []byte{9}, PublicKey: []byte{8}}
	src.Attestation.Object = []byte{0xa0, 0x01, 0x02}
	apiCred := CredentialToAPI(src, 1, "key")
	if len(apiCred.RawAttestation) == 0 {
		t.Fatal("setup: expected non-empty RawAttestation from CredentialToAPI")
	}

	// when converting back to a webauthn credential
	got := APICredentialToWebAuthn(apiCred)

	// then the attestation object is restored byte-for-byte
	if !bytes.Equal(got.Attestation.Object, []byte{0xa0, 0x01, 0x02}) {
		t.Errorf("APICredentialToWebAuthn restored Attestation.Object = %v, want %v",
			got.Attestation.Object, []byte{0xa0, 0x01, 0x02})
	}
}

// recordingHandler captures every slog.Record regardless of level.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
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

// --- APICredentialToWebAuthn L175 boundary: if len(c.RawAttestation) > 0 ---
//
// With an empty RawAttestation the unmarshal branch must NOT run, so no
// corruption warning is logged. The boundary mutant (> 0 → >= 0) would attempt
// to unmarshal an empty payload, fail, and log a warning.
func TestAPICredentialToWebAuthn_empty_raw_attestation_no_warning(t *testing.T) {
	h := withCapturedDefaultLogger(t)

	// given a credential with no raw attestation
	cred := &auth.PasskeyCredential{
		CredentialID: []byte{1},
		PublicKey:    []byte{2},
		AAGUID:       make([]byte, 16),
	}

	// when converting it
	_ = APICredentialToWebAuthn(cred)

	// then no corrupted-attestation warning is emitted
	if n := h.countMsg("corrupted attestation"); n != 0 {
		t.Errorf("APICredentialToWebAuthn(empty RawAttestation) logged %d corrupted-attestation warnings, want 0", n)
	}
}

// --- APICredentialToWebAuthn L176 negation: if err := json.Unmarshal(...); err != nil ---
//
// With a non-empty but invalid RawAttestation the unmarshal fails and a warning
// must be logged. The negation mutant (err != nil → err == nil) would suppress
// the warning on failure.
func TestAPICredentialToWebAuthn_invalid_raw_attestation_warns(t *testing.T) {
	h := withCapturedDefaultLogger(t)

	// given a credential with corrupted raw attestation JSON
	cred := &auth.PasskeyCredential{
		CredentialID:   []byte{1},
		PublicKey:      []byte{2},
		AAGUID:         make([]byte, 16),
		RawAttestation: []byte("not valid json"),
	}

	// when converting it
	_ = APICredentialToWebAuthn(cred)

	// then exactly one corrupted-attestation warning is emitted
	if n := h.countMsg("corrupted attestation"); n != 1 {
		t.Errorf("APICredentialToWebAuthn(invalid RawAttestation) logged %d corrupted-attestation warnings, want 1", n)
	}
}
