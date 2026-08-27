package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// This file mirrors the two WebAuthn options dictionaries as first-party types,
// so a consumer can serialize what a Begin* call returns without importing
// go-webauthn. The shape is fixed by the specification rather than by this
// library or by upstream: these are §5.4 PublicKeyCredentialCreationOptions and
// §5.5 PublicKeyCredentialRequestOptions, whose members are camelCase JSON that
// the browser's own parsers read, so no member may be renamed on either side.
//
// It restates the IDL rather than copying upstream's structs. Upstream carries
// internal ceremony state in the same values (an Origin it never serializes, and
// attestation bookkeeping on a descriptor), and copying those would invite a
// caller to set a field that never reaches the wire.
//
// Conversion is field by field, deliberately. A JSON round-trip through upstream
// would be shorter and would silently drop any member added upstream; an
// explicit assignment turns that into a compile error here, which is the whole
// reason these types are first-party.

// Base64URL is a byte string that travels as unpadded base64url, the encoding
// every binary member of the options dictionaries uses.
type Base64URL []byte

// MarshalJSON encodes the bytes as an unpadded base64url JSON string.
func (b Base64URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON decodes an unpadded base64url JSON string. Padded input is
// accepted too, because some clients emit it.
func (b *Base64URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.WithPadding(base64.StdPadding).DecodeString(s)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("auth/webauthn: value is not base64url: %w", err)
		}
	}
	*b = decoded
	return nil
}

// CredentialType is the credential type of a public key credential. The
// specification defines exactly one value and marks the enumeration extensible.
type CredentialType string

// PublicKeyCredentialType is the only credential type WebAuthn defines.
const PublicKeyCredentialType CredentialType = "public-key"

// AuthenticatorTransport is a transport an authenticator may be reached over.
// Clients must ignore a value they do not know, so this list is not exhaustive
// of what may arrive.
type AuthenticatorTransport string

// The transports defined by WebAuthn §5.8.4.
const (
	TransportUSB       AuthenticatorTransport = "usb"
	TransportNFC       AuthenticatorTransport = "nfc"
	TransportBLE       AuthenticatorTransport = "ble"
	TransportSmartCard AuthenticatorTransport = "smart-card"
	TransportHybrid    AuthenticatorTransport = "hybrid"
	TransportInternal  AuthenticatorTransport = "internal"
)

// UserVerificationRequirement is the relying party's user-verification
// requirement for a ceremony.
type UserVerificationRequirement string

// The user-verification requirements defined by WebAuthn §5.8.6.
const (
	VerificationRequired    UserVerificationRequirement = "required"
	VerificationPreferred   UserVerificationRequirement = "preferred"
	VerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// ResidentKeyRequirement is the relying party's requirement for a
// client-side discoverable credential.
type ResidentKeyRequirement string

// The resident-key requirements defined by WebAuthn §5.4.6.
const (
	ResidentKeyDiscouraged ResidentKeyRequirement = "discouraged"
	ResidentKeyPreferred   ResidentKeyRequirement = "preferred"
	ResidentKeyRequired    ResidentKeyRequirement = "required"
)

// ConveyancePreference is the relying party's attestation-conveyance
// preference. This library requests the specification's default, so it does not
// set the member.
type ConveyancePreference string

// The attestation-conveyance preferences defined by WebAuthn §5.4.7.
const (
	ConveyanceNone       ConveyancePreference = "none"
	ConveyanceIndirect   ConveyancePreference = "indirect"
	ConveyanceDirect     ConveyancePreference = "direct"
	ConveyanceEnterprise ConveyancePreference = "enterprise"
)

// AttestationStatementFormat is an attestation statement format identifier the
// relying party will accept.
type AttestationStatementFormat string

// The attestation statement formats registered by WebAuthn §8.
const (
	AttestationFormatPacked           AttestationStatementFormat = "packed"
	AttestationFormatTPM              AttestationStatementFormat = "tpm"
	AttestationFormatAndroidKey       AttestationStatementFormat = "android-key"
	AttestationFormatAndroidSafetyNet AttestationStatementFormat = "android-safetynet"
	AttestationFormatFIDOU2F          AttestationStatementFormat = "fido-u2f"
	AttestationFormatApple            AttestationStatementFormat = "apple"
	AttestationFormatCompound         AttestationStatementFormat = "compound"
	AttestationFormatNone             AttestationStatementFormat = "none"
)

// CredentialHint guides the client's user interface toward a kind of
// authenticator. It is a hint, so a client may ignore it.
type CredentialHint string

// The hints defined by WebAuthn §5.8.7.
const (
	HintSecurityKey  CredentialHint = "security-key"
	HintClientDevice CredentialHint = "client-device"
	HintHybrid       CredentialHint = "hybrid"
)

// Mediation is the credential-mediation requirement, which decides how much the
// client may complete a ceremony without an explicit user gesture.
type Mediation string

// The mediation requirements defined by the Credential Management specification.
const (
	MediationSilent      Mediation = "silent"
	MediationOptional    Mediation = "optional"
	MediationConditional Mediation = "conditional"
	MediationRequired    Mediation = "required"
)

// COSEAlgorithm is a COSE algorithm identifier, the value a relying party names
// to ask for a particular signature algorithm.
type COSEAlgorithm int

// RelyingPartyEntity describes the relying party a credential is registered to
// (WebAuthn §5.4.2).
type RelyingPartyEntity struct {
	// Name is the human-palatable relying party name, for display only.
	Name string `json:"name"`
	// ID is the relying party identifier, which sets the RP ID.
	ID string `json:"id"`
}

// UserEntity describes the user account a credential is registered to
// (WebAuthn §5.4.3).
type UserEntity struct {
	// Name is a human-palatable account identifier, for display only.
	Name string `json:"name"`
	// DisplayName is a human-palatable name for the account holder, for display
	// only.
	DisplayName string `json:"displayName"`
	// ID is the user handle. Authentication and authorization decisions are made
	// on this value, never on the two names above.
	ID Base64URL `json:"id"`
}

// CredentialParameter names a credential type and signature algorithm the
// relying party will accept (WebAuthn §5.3).
type CredentialParameter struct {
	Type      CredentialType `json:"type"`
	Algorithm COSEAlgorithm  `json:"alg"`
}

// CredentialDescriptor refers to an existing credential (WebAuthn §5.8.3). It
// carries only the three IDL members; upstream's equivalent also holds
// attestation bookkeeping that is never serialized.
type CredentialDescriptor struct {
	Type       CredentialType           `json:"type"`
	ID         Base64URL                `json:"id"`
	Transports []AuthenticatorTransport `json:"transports,omitempty"`
}

// AuthenticatorSelection is the relying party's criteria for which
// authenticators may be used (WebAuthn §5.4.4).
type AuthenticatorSelection struct {
	ResidentKey      ResidentKeyRequirement      `json:"residentKey,omitempty"`
	UserVerification UserVerificationRequirement `json:"userVerification,omitempty"`
}

// RegistrationExtensions are the client extension inputs a registration
// requests. It carries only credProps, because that is the only extension this
// library requests; an extension that is not requested is never reported, so a
// member for one would always be false.
type RegistrationExtensions struct {
	// CredProps requests the Credential Properties extension, whose output tells
	// the relying party whether the new credential is discoverable.
	CredProps bool `json:"credProps,omitempty"`
}

// CredentialCreationOptions is WebAuthn §5.4
// PublicKeyCredentialCreationOptions: everything the client needs to create a
// credential.
type CredentialCreationOptions struct {
	RelyingParty           RelyingPartyEntity           `json:"rp"`
	AuthenticatorSelection AuthenticatorSelection       `json:"authenticatorSelection"`
	Attestation            ConveyancePreference         `json:"attestation,omitempty"`
	User                   UserEntity                   `json:"user"`
	Challenge              Base64URL                    `json:"challenge"`
	Parameters             []CredentialParameter        `json:"pubKeyCredParams,omitempty"`
	ExcludeCredentials     []CredentialDescriptor       `json:"excludeCredentials,omitempty"`
	Hints                  []CredentialHint             `json:"hints,omitempty"`
	AttestationFormats     []AttestationStatementFormat `json:"attestationFormats,omitempty"`
	Timeout                int                          `json:"timeout,omitempty"`
	Extensions             RegistrationExtensions       `json:"extensions"`
}

// CredentialRequestOptions is WebAuthn §5.5
// PublicKeyCredentialRequestOptions: everything the client needs to produce an
// assertion.
type CredentialRequestOptions struct {
	RelyingPartyID   string                      `json:"rpId,omitempty"`
	UserVerification UserVerificationRequirement `json:"userVerification,omitempty"`
	Challenge        Base64URL                   `json:"challenge"`
	AllowCredentials []CredentialDescriptor      `json:"allowCredentials,omitempty"`
	Hints            []CredentialHint            `json:"hints,omitempty"`
	Timeout          int                         `json:"timeout,omitempty"`
}

// CredentialCreation is what a registration ceremony hands the browser. The
// publicKey member is the name navigator.credentials.create() reads, so it is
// the specification yielding rather than this fleet's JSON convention breaking.
type CredentialCreation struct {
	Response CredentialCreationOptions `json:"publicKey"`
}

// CredentialAssertion is what a login ceremony hands the browser.
type CredentialAssertion struct {
	Mediation Mediation                `json:"mediation,omitempty"`
	Response  CredentialRequestOptions `json:"publicKey"`
}
