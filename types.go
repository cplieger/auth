package auth

import "time"

// Method is a typed identifier for the authentication mechanism used
// to establish a session.
type Method string

// Auth method identifiers stored in sessions and used for method guards.
const (
	MethodPassword Method = "password"
	MethodPasskey  Method = "passkey"
	MethodOIDC     Method = "oidc"
)

// Role is a typed string identifying a user's authorization level.
type Role string

// User role constants.
const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// User represents an authenticated user account.
type User struct {
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Username     string    `json:"username"`
	Email        string    `json:"email,omitempty"`
	DisplayName  string    `json:"display_name,omitempty"`
	PasswordHash string    `json:"-"`
	Role         Role      `json:"role"`
	OIDCSub      string    `json:"-"`
	OIDCIssuer   string    `json:"-"`

	// WebAuthnHandle is the account's WebAuthn user handle, the value an
	// authenticator stores to identify this account and returns during a
	// discoverable login. Set it with [GenerateWebAuthnHandle] when creating an
	// account, and never change it afterwards: every passkey already registered
	// is bound to the value in force at its registration, so a new handle
	// orphans all of them.
	//
	// It is deliberately not derived from any other field. An authenticator may
	// reveal a handle without verifying the user, so it must say nothing about
	// who the account belongs to.
	WebAuthnHandle []byte `json:"-"`

	ID      int64 `json:"id"`
	Enabled bool  `json:"-"`
}

// Session represents a server-side authenticated session.
type Session struct {
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	// OIDCExpiry is the underlying OIDC token's expiry, or the zero Time when
	// the session is not OIDC-backed or the provider issued no expiry. It is a
	// value, not a *time.Time: time.Time's zero value already encodes absence
	// (see [time.Time.IsZero]), so the pointer bought nothing and cost two
	// things — a nil dereference for any caller that read it without the nil
	// check, and a shared mutable cell, since a struct copy of a Session
	// carrying a pointer still aliases the pointee.
	OIDCExpiry time.Time `json:"oidc_expiry,omitzero"`
	TokenHash  string    `json:"-"`
	AuthMethod Method    `json:"auth_method"`
	IPAddress  string    `json:"ip_address"`
	UserID     int64     `json:"user_id"`
}

// AuthenticatorAttachment reports how the authenticator that created a
// credential is attached to the client device.
type AuthenticatorAttachment string

// The attachment modalities defined by WebAuthn §5.4.5. The zero value means
// the client did not report one, which is legal.
const (
	AttachmentPlatform      AuthenticatorAttachment = "platform"
	AttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// PasskeyCredential represents a WebAuthn/FIDO2 credential registered to a user.
//
// The field set is the credential record of WebAuthn §Credential Record. Every
// item that specification lists as RECOMMENDED is here, so a store persisting
// all of it can execute both the registration and the assertion algorithms; the
// optional items are here too, because a record written without them cannot be
// backfilled later — the data was never conveyed.
type PasskeyCredential struct {
	CreatedAt time.Time `json:"created_at"`

	// Discoverable is the credProps.rk extension output: whether the credential
	// is client-side discoverable. Nil means the client did not report it, which
	// is distinct from a reported false. This library requests credProps on
	// every registration and refuses a credential reported as non-discoverable,
	// so a stored false should not occur; nil is normal.
	//
	// It is the only extension output stored, because it is the only one this
	// library requests. An extension that is not requested is not reported, so a
	// field for it would be permanently zero.
	Discoverable *bool `json:"-"`

	// AttestationType is the attestation type conveyed at registration
	// ("basic_full", "basic_surrogate", "attca", "anonca", "ecdaa", "none").
	AttestationType string `json:"-"`

	// AttestationFormat is the attestation statement format identifier
	// ("packed", "tpm", "android-key", "android-safetynet", "fido-u2f",
	// "apple", "compound", "none").
	AttestationFormat string `json:"-"`

	// RPID is the relying-party ID the credential was registered against. It
	// decides where the credential can be used, so a change to the relying
	// party's ID can be audited against it rather than silently orphaning every
	// passkey.
	RPID string `json:"-"`

	Transport string `json:"transport,omitempty"`
	Name      string `json:"name"`

	// Attachment is how the authenticator was attached at registration. Empty
	// when the client did not report it.
	Attachment AuthenticatorAttachment `json:"-"`

	CredentialID   []byte `json:"-"`
	PublicKey      []byte `json:"-"`
	AAGUID         []byte `json:"-"`
	RawAttestation []byte `json:"-"`

	ID     int64 `json:"id"`
	UserID int64 `json:"user_id"`

	SignCount uint32 `json:"-"`

	// RawFlags is the authenticator-data flags octet as conveyed at
	// registration, and it is the ONLY flag input this library reads. The
	// booleans below are a decoded view for a consumer to display or filter on;
	// nothing here reads them back, so a store that persists them and drops the
	// octet loses the flags. The octet also preserves the bits the booleans do
	// not (AT, ED), which no accessor exposes.
	//
	// A store MUST persist it. A real registration always sets user presence,
	// so a zero octet on a stored credential means the store did not record it,
	// and the flags it restores are all false — which go-webauthn refuses at
	// the next login when the authenticator asserts backup eligibility (see
	// the PASSKEY FLAGS note in store_contract.go).
	RawFlags uint8 `json:"-"`

	BackupEligible bool `json:"backup_eligible"`
	BackupState    bool `json:"-"`
	UserPresent    bool `json:"-"`

	// UserVerified is the specification's uvInitialized: it latches true once
	// any assertion has verified the user. To decide whether one PARTICULAR
	// ceremony verified the user, read that ceremony's own authenticator data.
	UserVerified bool `json:"-"`

	CloneWarning bool `json:"-"`
}

// PasskeyFlags holds the boolean authenticator flags for a credential update.
type PasskeyFlags struct {
	UserPresent    bool
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
	CloneWarning   bool
}

// PasskeyRef identifies one passkey credential together with the user who
// must own it. Rename/delete operations take the pair as one value so the
// ownership check cannot be silently disarmed by swapping two adjacent int64
// arguments: the field names make each value's role explicit at the call site.
// The zero value identifies nothing: no stored credential has ID or UserID
// zero, so an operation given a zero or partial ref affects no row (fails
// closed).
type PasskeyRef struct {
	// ID is the credential row ID (PasskeyCredential.ID).
	ID int64
	// UserID is the owning user; an operation must affect the credential only
	// when it belongs to this user.
	UserID int64
}

// KeyRef identifies one API key together with the user who must own it.
// See [PasskeyRef] for why the pair travels as one value. The zero value
// identifies nothing: no stored key has ID or UserID zero, so an operation
// given a zero or partial ref affects no row (fails closed).
type KeyRef struct {
	// ID is the key row ID (Key.ID).
	ID int64
	// UserID is the owning user; an operation must affect the key only when
	// it belongs to this user.
	UserID int64
}

// Key represents a machine-to-machine API key for a user.
type Key struct {
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is when the key stops being accepted, or the zero Time for a
	// key that never expires. See [Session.OIDCExpiry] for why an optional
	// timestamp is a value here rather than a *time.Time.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	KeyHash   string    `json:"-"`
	KeyPrefix string    `json:"key_prefix"`
	KeySuffix string    `json:"key_suffix"`
	Label     string    `json:"label"`
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
}

// OIDCConfig holds OIDC provider settings.
type OIDCConfig struct {
	IssuerURL    string `json:"issuer_url" yaml:"issuer_url"`
	ClientID     string `json:"client_id" yaml:"client_id"`
	ClientSecret string `json:"-" yaml:"client_secret"`
	RedirectURI  string `json:"redirect_uri" yaml:"redirect_uri"`
	AutoRedirect bool   `json:"auto_redirect" yaml:"auto_redirect"`
}

// HeaderXAPIKey is the HTTP header carrying the API key. Keys are accepted only
// via this header, never a URL query parameter; a query-string key leaks into
// access logs, browser history, and the Referer header (CWE-598).
const HeaderXAPIKey = "X-Api-Key" //nolint:gosec // G101 false positive: header name, not a credential
