// Package webauthn wraps go-webauthn/webauthn to provide WebAuthn/FIDO2
// passkey ceremony helpers. It imports the core auth package for types
// but never the reverse.
package webauthn

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cplieger/auth"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// CeremonyTimeout is the maximum duration a user has to complete an auth ceremony.
const CeremonyTimeout = 5 * time.Minute

// Store is the narrow interface consumed by WebAuthn/passkey handlers.
type Store interface {
	GetPasskeysByUserID(ctx context.Context, userID int64) ([]auth.PasskeyCredential, error)
	UpdatePasskeyAfterLogin(ctx context.Context, credID []byte, signCount uint32, flags auth.PasskeyFlags) error
	GetUserByID(ctx context.Context, id int64) (*auth.User, error)
}

const (
	credNameWindowsHello = "Windows Hello"
	credNameChromeOnMac  = "Chrome on Mac" //nolint:gosec // G101 false positive: authenticator display name, not a credential
	aaguidChromeOnMac    = "adce0002-35bc-c60a-648b-0b25f1f05503"
)

// User adapts auth.User + credentials to the webauthn.User interface.
type User struct {
	AuthUser    *auth.User
	Credentials []auth.PasskeyCredential
}

// NewWebAuthnUser returns a User with the given user and credentials.
func NewWebAuthnUser(user *auth.User, creds []auth.PasskeyCredential) (*User, error) {
	if user == nil {
		return nil, errors.New("auth/webauthn: NewWebAuthnUser called with nil user")
	}
	return &User{AuthUser: user, Credentials: creds}, nil
}

// WebAuthnID encodes the user ID as a binary varint.
func (u *User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(buf, u.AuthUser.ID)
	return buf[:n]
}

// WebAuthnName returns the username.
func (u *User) WebAuthnName() string {
	return u.AuthUser.Username
}

// WebAuthnDisplayName returns the display name, falling back to username.
func (u *User) WebAuthnDisplayName() string {
	if u.AuthUser.DisplayName != "" {
		return u.AuthUser.DisplayName
	}
	return u.AuthUser.Username
}

// WebAuthnCredentials converts the stored credentials to webauthn.Credential.
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.Credentials))
	for i := range u.Credentials {
		creds[i] = APICredentialToWebAuthn(&u.Credentials[i])
	}
	return creds
}

// AAGUIDEntry maps an authenticator AAGUID to a friendly name.
type AAGUIDEntry struct {
	UUID string
	Name string
}

// KnownAAGUIDs is the registry of known authenticator AAGUIDs.
var KnownAAGUIDs = []AAGUIDEntry{
	{"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", "Google Password Manager"},
	{aaguidChromeOnMac, credNameChromeOnMac},
	{"08987058-cadc-4b81-b6e1-30de50dcbe96", credNameWindowsHello},
	{"9ddd1817-af5a-4672-a2b9-3e3dd95000a9", credNameWindowsHello},
	{"6028b017-b1d4-4c02-b4b3-afcdafc96bb2", credNameWindowsHello},
	{"dd4ec289-e01d-41c9-bb89-70fa845d4bf2", "iCloud Keychain"},
	{"fbfc3007-154e-4ecc-8c0b-6e020557d7bd", "iCloud Keychain"},
	{"d548826e-79b4-db40-a3d8-11116f7e8349", "Bitwarden"},
	{"b5397723-31d4-4c13-b037-37be46e30e9e", "1Password"},
	{"bada5566-a7aa-401f-bd96-45619a55120d", "1Password"},
	{"2fc0579f-8113-47ea-b116-bb5a8db9202a", "YubiKey 5"},
	{"fa2b99dc-9e39-4257-8f92-4a30d23c4118", "YubiKey 5 NFC"},
}

var knownAAGUIDMap = func() map[string]string {
	m := make(map[string]string, len(KnownAAGUIDs))
	for _, e := range KnownAAGUIDs {
		m[e.UUID] = e.Name
	}
	return m
}()

// formatAAGUID formats a 16-byte AAGUID as a UUID string (8-4-4-4-12).
func formatAAGUID(aaguid []byte) string {
	if len(aaguid) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		aaguid[0:4], aaguid[4:6], aaguid[6:8], aaguid[8:10], aaguid[10:16])
}

// PasskeyFriendlyName returns a human-friendly name for a passkey based on
// its AAGUID.
func PasskeyFriendlyName(aaguid []byte, existingNames []string) string {
	uuid := formatAAGUID(aaguid)
	baseName, known := knownAAGUIDMap[uuid]
	if !known {
		n := 1
		for _, name := range existingNames {
			if name == "Passkey" || strings.HasPrefix(name, "Passkey ") {
				n++
			}
		}
		return fmt.Sprintf("Passkey %d", n)
	}

	count := 0
	for _, name := range existingNames {
		if name == baseName || strings.HasPrefix(name, baseName+" ") {
			count++
		}
	}
	if count == 0 {
		return baseName
	}
	return fmt.Sprintf("%s %d", baseName, count+1)
}

// APICredentialToWebAuthn converts a PasskeyCredential to a webauthn.Credential.
func APICredentialToWebAuthn(c *auth.PasskeyCredential) webauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	if c.Transport != "" {
		for t := range strings.SplitSeq(c.Transport, ",") {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}

	cred := webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			UserPresent:    c.UserPresent,
			UserVerified:   c.UserVerified,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    c.SignCount,
			CloneWarning: c.CloneWarning,
		},
	}

	if len(c.RawAttestation) > 0 {
		if err := json.Unmarshal(c.RawAttestation, &cred.Attestation); err != nil {
			slog.Warn("webauthn: corrupted attestation data, skipping MDS verification",
				"credential_id", hex.EncodeToString(c.CredentialID[:min(8, len(c.CredentialID))]),
				"error", err)
		}
	}

	return cred
}

// CredentialToAPI converts a webauthn.Credential to a PasskeyCredential.
func CredentialToAPI(c *webauthn.Credential, userID int64, name string) *auth.PasskeyCredential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}

	var rawAttestation []byte
	if len(c.Attestation.Object) > 0 || len(c.Attestation.ClientDataJSON) > 0 {
		var err error
		rawAttestation, err = json.Marshal(c.Attestation)
		if err != nil {
			slog.Warn("webauthn: failed to marshal attestation data",
				"credential_id", hex.EncodeToString(c.ID[:min(8, len(c.ID))]),
				"error", err)
			rawAttestation = nil
		}
	}

	return &auth.PasskeyCredential{
		UserID:          userID,
		CredentialID:    c.ID,
		PublicKey:       c.PublicKey,
		AAGUID:          c.Authenticator.AAGUID,
		AttestationType: c.AttestationType,
		Transport:       strings.Join(transports, ","),
		SignCount:       c.Authenticator.SignCount,
		Name:            name,
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
		UserPresent:     c.Flags.UserPresent,
		UserVerified:    c.Flags.UserVerified,
		CloneWarning:    c.Authenticator.CloneWarning,
		RawAttestation:  rawAttestation,
	}
}

// NewWebAuthn creates a configured webauthn.WebAuthn instance.
func NewWebAuthn(rpID, rpDisplayName string, rpOrigins []string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    CeremonyTimeout,
				TimeoutUVD: CeremonyTimeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    CeremonyTimeout,
				TimeoutUVD: CeremonyTimeout,
			},
		},
	})
}

// BeginRegistration starts a WebAuthn registration ceremony.
func BeginRegistration(wa *webauthn.WebAuthn, user *User) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
		webauthn.WithExtensions(map[string]any{"credProps": true}),
	)
}

// FinishRegistration completes a WebAuthn registration ceremony.
func FinishRegistration(wa *webauthn.WebAuthn, user *User, sessionData *webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	return wa.FinishRegistration(user, *sessionData, response)
}

// BeginLogin starts a WebAuthn assertion ceremony (discoverable login).
func BeginLogin(wa *webauthn.WebAuthn) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
}

// BeginConditionalLogin starts a WebAuthn assertion ceremony with conditional
// mediation, enabling browser autofill UI for passkeys.
func BeginConditionalLogin(wa *webauthn.WebAuthn) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return wa.BeginDiscoverableMediatedLogin(protocol.MediationConditional,
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
}

// FinishLogin completes a WebAuthn assertion ceremony (discoverable login).
func FinishLogin(wa *webauthn.WebAuthn, sessionData *webauthn.SessionData, response *http.Request, userFinder func(rawID, userHandle []byte) (webauthn.User, error)) (webauthn.User, *webauthn.Credential, error) {
	return wa.FinishPasskeyLogin(userFinder, *sessionData, response)
}
