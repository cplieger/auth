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
	CreatedAt    time.Time  `json:"created_at"`
	LastActivity time.Time  `json:"last_activity"`
	OIDCExpiry   *time.Time `json:"oidc_expiry,omitempty"`
	TokenHash    string     `json:"-"`
	AuthMethod   Method     `json:"auth_method"`
	IPAddress    string     `json:"ip_address"`
	UserID       int64      `json:"user_id"`
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

// Key represents a machine-to-machine API key for a user.
type Key struct {
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	KeyHash   string     `json:"-"`
	KeyPrefix string     `json:"key_prefix"`
	KeySuffix string     `json:"key_suffix"`
	Label     string     `json:"label"`
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
}

// OIDCConfig holds OIDC provider settings.
type OIDCConfig struct {
	IssuerURL    string `json:"issuer_url" yaml:"issuer_url"`
	ClientID     string `json:"client_id" yaml:"client_id"`
	ClientSecret string `json:"-" yaml:"client_secret"`
	RedirectURI  string `json:"redirect_uri" yaml:"redirect_uri"`
	AutoRedirect bool   `json:"auto_redirect" yaml:"auto_redirect"`
}

// HTTP header and query parameter constants for API key authentication.
const (
	HeaderXAPIKey    = "X-Api-Key" //nolint:gosec // G101 false positive: header name, not a credential
	QueryParamAPIKey = "api_key"
)
