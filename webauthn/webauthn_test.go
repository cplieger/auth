package webauthn

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"uuid"

	"github.com/cplieger/auth/v4"
	"github.com/cplieger/auth/v4/internal/capture"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// parseAAGUID parses a UUID string into 16 bytes.
func parseAAGUID(s string) []byte {
	u, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return u[:]
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

func TestCredentialFromAPI_table(t *testing.T) {
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
			got := CredentialFromAPI(cred)
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

func TestCredentialFromAPI_corrupted_attestation(t *testing.T) {
	t.Parallel()
	cred := &auth.PasskeyCredential{
		CredentialID:   []byte{1},
		PublicKey:      []byte{2},
		AAGUID:         make([]byte, 16),
		RawAttestation: []byte("not valid json"),
	}
	got := CredentialFromAPI(cred)
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
	waCred := CredentialFromAPI(cred)
	if !waCred.Authenticator.CloneWarning {
		t.Error("CredentialFromAPI did not propagate CloneWarning")
	}
	back := CredentialToAPI(&waCred, 1, "test")
	if !back.CloneWarning {
		t.Error("CredentialToAPI did not propagate CloneWarning")
	}
}

func TestNew_valid_config(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	if wa == nil {
		t.Fatal("New returned nil")
	}
}

// New rejects an RPConfig with an empty ID at construction. Upstream
// go-webauthn validates only RPOrigins, so an empty RP ID would construct
// successfully and then fail every ceremony with an RP-hash mismatch
// (sha256("") can never equal a real RP hash); the wrapper exists to make the
// relying party legible, so the misconfiguration must surface here, naming
// the field.
func TestNew_empty_rp_id_rejected(t *testing.T) {
	t.Parallel()
	wa, err := New(RPConfig{DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err == nil {
		t.Fatal("New(RPConfig{ID: \"\"}) error = nil, want error naming RPConfig.ID")
	}
	if !strings.Contains(err.Error(), "RPConfig.ID") {
		t.Errorf("New(RPConfig{ID: \"\"}) error = %q, want it to name RPConfig.ID", err)
	}
	if wa != nil {
		t.Errorf("New(RPConfig{ID: \"\"}) = %v, want nil", wa)
	}
}

func TestBeginRegistration_with_user(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	user := &User{AuthUser: &auth.User{ID: 1, Username: "test"}}
	creation, session, err := BeginRegistration(wa, user)
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}
	if creation == nil {
		t.Error("BeginRegistration() creation = nil, want non-nil")
	}
	if session == nil {
		t.Error("BeginRegistration() session = nil, want non-nil")
	}
}

func TestBeginRegistration_requires_user_verification(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
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

// TestBeginRegistration_requires_resident_key pins ResidentKey=Required in the
// AuthenticatorSelection literal. Resident (discoverable) credentials are what
// make passkeys usable with BeginDiscoverableLogin/BeginConditionalLogin; an
// edit that dropped or weakened ResidentKey would silently break discoverable
// login while existing tests stayed green.
func TestBeginRegistration_requires_resident_key(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	user := &User{AuthUser: &auth.User{ID: 1, Username: "test"}}
	creation, _, err := BeginRegistration(wa, user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	rk := creation.Response.AuthenticatorSelection.ResidentKey
	if rk != protocol.ResidentKeyRequirementRequired {
		t.Errorf("ResidentKey = %q, want %q", rk, protocol.ResidentKeyRequirementRequired)
	}
}

func TestBeginLogin_requires_user_verification(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
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

// CredentialFromAPI restores a non-empty RawAttestation back into the
// credential's Attestation object byte-for-byte (the inverse of CredentialToAPI).
func TestCredentialFromAPI_restores_attestation_from_raw(t *testing.T) {
	t.Parallel()

	src := &gowebauthn.Credential{ID: []byte{9}, PublicKey: []byte{8}}
	src.Attestation.Object = []byte{0xa0, 0x01, 0x02}
	apiCred := CredentialToAPI(src, 1, "key")
	if len(apiCred.RawAttestation) == 0 {
		t.Fatal("setup: expected non-empty RawAttestation from CredentialToAPI")
	}

	got := CredentialFromAPI(apiCred)

	if !bytes.Equal(got.Attestation.Object, []byte{0xa0, 0x01, 0x02}) {
		t.Errorf("CredentialFromAPI restored Attestation.Object = %v, want %v",
			got.Attestation.Object, []byte{0xa0, 0x01, 0x02})
	}
}

// An empty RawAttestation is skipped silently: CredentialFromAPI logs no
// corrupted-attestation warning when there is nothing to unmarshal.
func TestCredentialFromAPI_empty_raw_attestation_no_warning(t *testing.T) {
	h := capture.Default(t)

	cred := &auth.PasskeyCredential{
		CredentialID: []byte{1},
		PublicKey:    []byte{2},
		AAGUID:       make([]byte, 16),
	}

	_ = CredentialFromAPI(cred)

	if n := h.CountMsg("corrupted attestation"); n != 0 {
		t.Errorf("CredentialFromAPI(empty RawAttestation) logged %d corrupted-attestation warnings, want 0", n)
	}
}

// A non-empty but malformed RawAttestation is reported once as a
// corrupted-attestation warning and otherwise ignored.
func TestCredentialFromAPI_invalid_raw_attestation_warns(t *testing.T) {
	h := capture.Default(t)

	cred := &auth.PasskeyCredential{
		CredentialID:   []byte{1},
		PublicKey:      []byte{2},
		AAGUID:         make([]byte, 16),
		RawAttestation: []byte("not valid json"),
	}

	_ = CredentialFromAPI(cred)

	if n := h.CountMsg("corrupted attestation"); n != 1 {
		t.Errorf("CredentialFromAPI(invalid RawAttestation) logged %d corrupted-attestation warnings, want 1", n)
	}
}

func TestNewUser(t *testing.T) {
	t.Parallel()
	t.Run("nil user returns error", func(t *testing.T) {
		t.Parallel()
		u, err := NewUser(nil, nil)
		if err == nil {
			t.Fatal("NewUser(nil, ...) error = nil, want non-nil")
		}
		if u != nil {
			t.Errorf("NewUser(nil, ...) user = %v, want nil", u)
		}
	})
	t.Run("valid user returns populated adapter", func(t *testing.T) {
		t.Parallel()
		au := &auth.User{ID: 7, Username: "bob"}
		creds := []auth.PasskeyCredential{{CredentialID: []byte{1, 2}}}
		u, err := NewUser(au, creds)
		if err != nil {
			t.Fatalf("NewUser error = %v, want nil", err)
		}
		if u == nil {
			t.Fatal("NewUser user = nil, want non-nil")
		}
		if u.AuthUser != au {
			t.Error("NewUser did not store the provided AuthUser")
		}
		if len(u.Credentials) != 1 {
			t.Errorf("NewUser Credentials len = %d, want 1", len(u.Credentials))
		}
	})
}

func TestWebAuthnCredentials_converts_all(t *testing.T) {
	t.Parallel()
	u := &User{
		AuthUser: &auth.User{ID: 1, Username: "alice"},
		Credentials: []auth.PasskeyCredential{
			{CredentialID: []byte{1}, PublicKey: []byte{2}, AAGUID: make([]byte, 16), Transport: "internal"},
			{CredentialID: []byte{3}, PublicKey: []byte{4}, AAGUID: make([]byte, 16), Transport: "usb,nfc"},
		},
	}
	got := u.WebAuthnCredentials()
	if len(got) != 2 {
		t.Fatalf("WebAuthnCredentials() len = %d, want 2", len(got))
	}
	if !bytes.Equal(got[0].ID, []byte{1}) {
		t.Errorf("WebAuthnCredentials()[0].ID = %v, want [1]", got[0].ID)
	}
	if len(got[1].Transport) != 2 {
		t.Errorf("WebAuthnCredentials()[1].Transport count = %d, want 2", len(got[1].Transport))
	}
}

func TestPasskeyFriendlyName_unknown_numbered(t *testing.T) {
	t.Parallel()
	aaguid := parseAAGUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	got := PasskeyFriendlyName(aaguid, []string{"Passkey 1", "Passkey 2"})
	if got != "Passkey 3" {
		t.Errorf("PasskeyFriendlyName(unknown, [Passkey 1, Passkey 2]) = %q, want %q", got, "Passkey 3")
	}
}

// TestBeginConditionalLogin_enforces_conditional_mediation_and_uv pins the two
// security-relevant ceremony options of the conditional-mediation login helper:
// conditional mediation (the browser autofill UI that distinguishes it from
// BeginLogin) and required user verification.
func TestBeginConditionalLogin_enforces_conditional_mediation_and_uv(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	assertion, session, err := BeginConditionalLogin(wa)
	if err != nil {
		t.Fatalf("BeginConditionalLogin: %v", err)
	}
	if assertion == nil || session == nil {
		t.Fatal("BeginConditionalLogin returned nil assertion or session")
	}
	if assertion.Mediation != protocol.MediationConditional {
		t.Errorf("Mediation = %q, want %q", assertion.Mediation, protocol.MediationConditional)
	}
	if uv := assertion.Response.UserVerification; uv != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want %q", uv, protocol.VerificationRequired)
	}
}

// TestPasskeyFriendlyName_numbering_gap_no_collision pins the max-suffix fix: the
// numeric suffix is one past the highest existing suffix, not a count of
// matches, so a non-tail deletion that leaves a gap cannot produce a duplicate
// label. The old count-based logic returned "Passkey 2" / "Chrome on Mac 2"
// for the first two cases, colliding with the survivor.
func TestPasskeyFriendlyName_numbering_gap_no_collision(t *testing.T) {
	t.Parallel()
	unknown := parseAAGUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	chrome := parseAAGUID("adce0002-35bc-c60a-648b-0b25f1f05503") // "Chrome on Mac"
	tests := []struct {
		name     string
		aaguid   []byte
		existing []string
		want     string
	}{
		{"unknown after non-tail delete", unknown, []string{"Passkey 2"}, "Passkey 3"},
		{"known after non-tail delete", chrome, []string{"Chrome on Mac 2"}, "Chrome on Mac 3"},
		{"known bare counts as suffix 1", chrome, []string{"Chrome on Mac", "Chrome on Mac 3"}, "Chrome on Mac 4"},
		{"non-numeric suffix ignored", unknown, []string{"Passkey two"}, "Passkey 1"},
		// A known base ("YubiKey 5") that is a space-prefix of another known
		// base ("YubiKey 5 NFC"): an existing "YubiKey 5 NFC" must NOT be
		// counted as a "YubiKey 5" variant, so the first plain YubiKey 5 stays
		// bare instead of becoming "YubiKey 5 1".
		{"known-prefix sibling not counted", parseAAGUID("2fc0579f-8113-47ea-b116-bb5a8db9202a"), []string{"YubiKey 5 NFC"}, "YubiKey 5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PasskeyFriendlyName(tc.aaguid, tc.existing)
			if got != tc.want {
				t.Errorf("PasskeyFriendlyName(%v) = %q, want %q", tc.existing, got, tc.want)
			}
			if slices.Contains(tc.existing, got) {
				t.Errorf("PasskeyFriendlyName returned %q, which collides with an existing name", got)
			}
		})
	}
}

// TestPasskeyFriendlyName_single_numbered_entry pins the lower suffix boundary
// of nameSuffix: a sole "base N" entry with N==1 (reached through the numbered
// "base N" parse path, not the bare name==base path) must count as suffix 1, so
// the next generated label is "base 2" and never re-collides with the existing
// "base 1". The existing numbering tests only pair a "base 1" with a higher
// "base 2", where the larger suffix dominates and masks a regression at the
// N==1 boundary.
func TestPasskeyFriendlyName_single_numbered_entry(t *testing.T) {
	t.Parallel()
	unknown := parseAAGUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
	chrome := parseAAGUID("adce0002-35bc-c60a-648b-0b25f1f05503") // "Chrome on Mac"
	tests := []struct {
		name     string
		aaguid   []byte
		existing []string
		want     string
	}{
		{"unknown sole numbered one", unknown, []string{"Passkey 1"}, "Passkey 2"},
		{"known sole numbered one", chrome, []string{"Chrome on Mac 1"}, "Chrome on Mac 2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PasskeyFriendlyName(tc.aaguid, tc.existing)
			if got != tc.want {
				t.Errorf("PasskeyFriendlyName(%v) = %q, want %q", tc.existing, got, tc.want)
			}
			if slices.Contains(tc.existing, got) {
				t.Errorf("PasskeyFriendlyName returned %q, which collides with an existing name", got)
			}
		})
	}
}

// TestBeginRegistration_enforces_ceremony_deadline pins the Enforce:true timeout
// posture of New. go-webauthn stamps a server-side deadline on the
// returned SessionData only when Registration.Enforce is set, so a non-zero
// Expires is the observable proof that an over-long registration ceremony is
// rejected at FinishRegistration. go-webauthn leaves Enforce at its false
// default, so dropping the Timeouts block from New would zero Expires
// and fail this test. The advisory timeout echoed to the browser equals
// CeremonyTimeout.
func TestBeginRegistration_enforces_ceremony_deadline(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	user := &User{AuthUser: &auth.User{ID: 1, Username: "test"}}
	creation, session, err := BeginRegistration(wa, user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if session == nil {
		t.Fatal("BeginRegistration returned nil session")
	}
	if session.Expires.IsZero() {
		t.Error("session.Expires is zero, want a server-side ceremony deadline (Registration.Enforce must be true)")
	}
	if got, want := creation.Response.Timeout, int(CeremonyTimeout.Milliseconds()); got != want {
		t.Errorf("creation.Response.Timeout = %d ms, want %d ms", got, want)
	}
}

// TestBeginRegistration_excludes_existing_credentials pins the WithExclusions
// wiring in BeginRegistration: a user's already-registered credentials are echoed
// into CredentialExcludeList so the authenticator refuses to create a duplicate
// passkey for the same user. Every other BeginRegistration test uses a
// credential-less user, so dropping WithExclusions would leave this list empty
// and go unnoticed.
func TestBeginRegistration_excludes_existing_credentials(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	user := &User{
		AuthUser: &auth.User{ID: 1, Username: "test"},
		Credentials: []auth.PasskeyCredential{
			{CredentialID: []byte{1, 2, 3}, PublicKey: []byte{9}, AAGUID: make([]byte, 16)},
			{CredentialID: []byte{4, 5, 6}, PublicKey: []byte{9}, AAGUID: make([]byte, 16)},
		},
	}
	creation, _, err := BeginRegistration(wa, user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	excludeList := creation.Response.CredentialExcludeList
	if len(excludeList) != 2 {
		t.Fatalf("CredentialExcludeList len = %d, want 2", len(excludeList))
	}
	if !bytes.Equal(excludeList[0].CredentialID, []byte{1, 2, 3}) {
		t.Errorf("CredentialExcludeList[0].CredentialID = %x, want 010203", excludeList[0].CredentialID)
	}
	if !bytes.Equal(excludeList[1].CredentialID, []byte{4, 5, 6}) {
		t.Errorf("CredentialExcludeList[1].CredentialID = %x, want 040506", excludeList[1].CredentialID)
	}
}

// TestBeginLogin_enforces_ceremony_deadline pins the Enforce:true posture for the
// login ceremony. New sets Login.Enforce, so BeginLogin's SessionData
// carries a non-zero server-side Expires deadline (go-webauthn rejects an expired
// assertion at FinishLogin). go-webauthn leaves Enforce false by default, so
// removing the Timeouts block from New would zero Expires and fail this
// test. The advisory timeout echoed to the client equals CeremonyTimeout.
func TestBeginLogin_enforces_ceremony_deadline(t *testing.T) {
	wa, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	assertion, session, err := BeginLogin(wa)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if session == nil {
		t.Fatal("BeginLogin returned nil session")
	}
	if session.Expires.IsZero() {
		t.Error("session.Expires is zero, want a server-side ceremony deadline (Login.Enforce must be true)")
	}
	if got, want := assertion.Response.Timeout, int(CeremonyTimeout.Milliseconds()); got != want {
		t.Errorf("assertion.Response.Timeout = %d ms, want %d ms", got, want)
	}
}
