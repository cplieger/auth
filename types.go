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
	ID           int64     `json:"id"`
	Enabled      bool      `json:"-"`
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

// PasskeyCredential represents a WebAuthn/FIDO2 credential registered to a user.
type PasskeyCredential struct {
	CreatedAt       time.Time `json:"created_at"`
	AttestationType string    `json:"-"`
	Transport       string    `json:"transport,omitempty"`
	Name            string    `json:"name"`
	CredentialID    []byte    `json:"-"`
	PublicKey       []byte    `json:"-"`
	AAGUID          []byte    `json:"-"`
	RawAttestation  []byte    `json:"-"`
	ID              int64     `json:"id"`
	UserID          int64     `json:"user_id"`
	SignCount       uint32    `json:"-"`
	BackupEligible  bool      `json:"backup_eligible"`
	BackupState     bool      `json:"-"`
	UserPresent     bool      `json:"-"`
	UserVerified    bool      `json:"-"`
	CloneWarning    bool      `json:"-"`
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
