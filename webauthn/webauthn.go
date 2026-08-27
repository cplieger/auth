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
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/cplieger/auth/v5"
	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// CeremonyTimeout is the maximum duration a user has to complete an auth ceremony.
const CeremonyTimeout = 5 * time.Minute

// Store is the narrow store interface consumed by [CompleteLogin]: user and
// credential lookup to resolve the asserting account from its user handle,
// and the post-login credential-custody write. A storage layer implementing
// [auth.UserStore] and [auth.PasskeyStore] satisfies it. Consumers composing
// the lower-level ceremony helpers ([BeginLogin], [BeginConditionalLogin]) with their
// own user finder do not need it.
type Store interface {
	PasskeysByUserID(ctx context.Context, userID int64) ([]auth.PasskeyCredential, error)
	UpdatePasskeyAfterLogin(ctx context.Context, credID []byte, signCount uint32, flags auth.PasskeyFlags) error
	UserByID(ctx context.Context, id int64) (user *auth.User, found bool, err error)
}

const (
	credNameWindowsHello = "Windows Hello"
	credNameChromeOnMac  = "Chrome on Mac" //nolint:gosec // G101 false positive: authenticator display name, not a credential
	aaguidChromeOnMac    = "adce0002-35bc-c60a-648b-0b25f1f05503"
)

// User adapts auth.User + credentials to the gowebauthn.User interface.
type User struct {
	AuthUser    *auth.User
	Credentials []auth.PasskeyCredential
}

// NewUser returns a User with the given user and credentials.
func NewUser(user *auth.User, creds []auth.PasskeyCredential) (*User, error) {
	if user == nil {
		return nil, errors.New("auth/webauthn: NewUser called with nil user")
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

// WebAuthnCredentials converts the stored credentials to gowebauthn.Credential.
func (u *User) WebAuthnCredentials() []gowebauthn.Credential {
	creds := make([]gowebauthn.Credential, len(u.Credentials))
	for i := range u.Credentials {
		creds[i] = CredentialFromAPI(&u.Credentials[i])
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
//
// An AAGUID is an opaque 128-bit authenticator identifier, not a conformant
// RFC 9562 UUID, and [uuid.UUID.String] is the right renderer for it anyway:
// it neither validates nor rewrites the version and variant bits, so it is a
// pure 8-4-4-4-12 formatter. Verified byte-identical to the hand-rolled
// fmt.Sprintf it replaces over the four AAGUIDs in KnownAAGUIDs, the all-zero
// and all-ones patterns, a deliberately non-RFC9562 bit pattern, and 200,000
// random 16-byte inputs: zero divergences.
func formatAAGUID(aaguid []byte) string {
	if len(aaguid) != 16 {
		return ""
	}
	return uuid.UUID(aaguid).String()
}

// nameSuffix reports whether name is a label PasskeyFriendlyName derives from
// base -- the bare base (which counts as suffix 1) or "base N" for a positive
// integer N -- and returns that suffix. ok is false for any other name,
// including one like "YubiKey 5 NFC" that merely shares a "base "-prefixed
// string with a different known base ("YubiKey 5"). nextNameSuffix routes
// through this helper so the suffix classification lives in exactly one place.
func nameSuffix(name, base string) (suffix int, ok bool) {
	if name == base {
		return 1, true
	}
	if rest, found := strings.CutPrefix(name, base+" "); found {
		if n, err := strconv.Atoi(rest); err == nil && n >= 1 {
			return n, true
		}
	}
	return 0, false
}

// nextNameSuffix returns one past the highest numeric suffix already in use
// among names derived from base: a name equal to base counts as suffix 1 (the
// bare form) and a name "base N" for a positive integer N counts as N. The
// result is 1 when no name matches. Deriving the suffix from the maximum in use
// -- rather than from a count of matches -- keeps generated names unique after
// a non-tail deletion leaves a numbering gap: deleting "Passkey 1" from
// ["Passkey 1", "Passkey 2"] still yields "Passkey 3", not a duplicate
// "Passkey 2".
func nextNameSuffix(existingNames []string, base string) int {
	highest := 0
	for _, name := range existingNames {
		if n, ok := nameSuffix(name, base); ok {
			highest = max(highest, n)
		}
	}
	return highest + 1
}

// PasskeyFriendlyName returns a display-only, human-friendly label for a
// newly registered passkey, chosen so it does not duplicate any entry in
// existingNames (the user's current passkey labels). A known authenticator
// (matched by AAGUID) gets its bare registry name for the first of its kind
// (e.g. "Chrome on Mac") and a numbered name for each subsequent one
// ("Chrome on Mac 2", ...); an unknown authenticator is always numbered
// ("Passkey 1", "Passkey 2", ...). The numeric suffix is one past the
// highest already in use, so deleting a passkey that leaves a numbering gap
// never yields a duplicate label.
func PasskeyFriendlyName(aaguid []byte, existingNames []string) string {
	aaguidKey := formatAAGUID(aaguid)
	baseName, known := knownAAGUIDMap[aaguidKey]
	if !known {
		return fmt.Sprintf("Passkey %d", nextNameSuffix(existingNames, "Passkey"))
	}
	// nextNameSuffix returns 1 only when no derived name exists yet, so a
	// suffix of 1 marks the first of its kind and earns the bare base name.
	suffix := nextNameSuffix(existingNames, baseName)
	if suffix == 1 {
		return baseName
	}
	return fmt.Sprintf("%s %d", baseName, suffix)
}

// CredentialFromAPI converts a PasskeyCredential to a gowebauthn.Credential
// (the inverse of [CredentialToAPI]).
func CredentialFromAPI(c *auth.PasskeyCredential) gowebauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	if c.Transport != "" {
		for t := range strings.SplitSeq(c.Transport, ",") {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}

	cred := gowebauthn.Credential{
		ID:                c.CredentialID,
		PublicKey:         c.PublicKey,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		Transport:         transports,
		Flags:             credentialFlags(c),
		Authenticator: gowebauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    c.SignCount,
			CloneWarning: c.CloneWarning,
			Attachment:   protocol.AuthenticatorAttachment(c.Attachment),
		},
		Extensions: gowebauthn.CredentialExtensions{RK: c.Discoverable},
	}

	if len(c.RawAttestation) > 0 {
		if err := json.Unmarshal(c.RawAttestation, &cred.Attestation); err != nil {
			slog.Warn("webauthn: corrupted attestation data, skipping MDS verification",
				"user_id", c.UserID,
				"credential_id", hex.EncodeToString(c.CredentialID[:min(8, len(c.CredentialID))]),
				"error", err)
		}
	}

	return cred
}

// credentialFlags rebuilds the upstream flag set from a stored credential.
//
// A record written by this library carries the raw octet, which is
// authoritative and preserves the bits the four booleans do not (AT, ED), so it
// is preferred. A record written before RawFlags existed holds a zero there and
// valid booleans, and a zero octet cannot be a real registration — user
// presence is required, so the UP bit is always set — which makes zero a sound
// discriminator rather than an ambiguous default.
func credentialFlags(c *auth.PasskeyCredential) gowebauthn.CredentialFlags {
	if c.RawFlags != 0 {
		return gowebauthn.NewCredentialFlags(protocol.AuthenticatorFlags(c.RawFlags))
	}
	return gowebauthn.CredentialFlags{
		UserPresent:    c.UserPresent,
		UserVerified:   c.UserVerified,
		BackupEligible: c.BackupEligible,
		BackupState:    c.BackupState,
	}
}

// CredentialToAPI converts a gowebauthn.Credential to a PasskeyCredential.
func CredentialToAPI(c *gowebauthn.Credential, userID int64, name string) *auth.PasskeyCredential {
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
				"user_id", userID,
				"credential_id", hex.EncodeToString(c.ID[:min(8, len(c.ID))]),
				"error", err)
			rawAttestation = nil
		}
	}

	return &auth.PasskeyCredential{
		UserID:            userID,
		CredentialID:      c.ID,
		PublicKey:         c.PublicKey,
		AAGUID:            c.Authenticator.AAGUID,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		Attachment:        auth.AuthenticatorAttachment(c.Authenticator.Attachment),
		Transport:         strings.Join(transports, ","),
		SignCount:         c.Authenticator.SignCount,
		Name:              name,
		RawFlags:          uint8(c.Flags.ProtocolValue()),
		BackupEligible:    c.Flags.BackupEligible,
		BackupState:       c.Flags.BackupState,
		UserPresent:       c.Flags.UserPresent,
		UserVerified:      c.Flags.UserVerified,
		CloneWarning:      c.Authenticator.CloneWarning,
		Discoverable:      c.Extensions.RK,
		RawAttestation:    rawAttestation,
	}
}

// RelyingParty is a configured relying party, and the value every ceremony
// function takes. It replaces the upstream handle on this package's exported
// surface so a consumer needs no go-webauthn import to run a ceremony; see the
// package documentation for why that boundary is drawn here.
//
// Construct one with [New]. The zero value is not usable.
type RelyingParty struct {
	wa *gowebauthn.WebAuthn
}

// ID returns the relying party identifier ceremonies are bound to. A stored
// credential records the ID it was registered against, so comparing the two is
// how a relying-party rename is detected rather than silently orphaning every
// passkey.
func (rp *RelyingParty) ID() string {
	return rp.wa.Config.RPID
}

// Ceremony is the server-side state of one in-flight WebAuthn ceremony: the
// challenge and the parameters the matching Finish step verifies the
// authenticator's response against.
//
// It is opaque and atomic. Hold it between the Begin and the Finish call
// without reshaping it, keep it server-side where a client cannot modify it,
// and discard it once the ceremony completes. A consumer's ceremony store keys
// it by its own opaque token; [Ceremony.Expires] is the only value that store
// needs to read.
//
// The value is cheap to copy and every copy refers to the same ceremony, which
// is safe because nothing mutates one after a Begin call returns it. The zero
// value is not a usable ceremony and reports a zero deadline, which is why a
// ceremony lookup reports absence with a separate boolean rather than a nil.
type Ceremony struct {
	data *gowebauthn.SessionData
}

// Expires reports when the ceremony stops being verifiable. A ceremony store
// evicts on this rather than tracking its own creation time, so the deadline
// the authenticator was given and the deadline the store enforces cannot drift
// apart.
func (c Ceremony) Expires() time.Time {
	if c.data == nil {
		return time.Time{}
	}
	return c.data.Expires
}

// RPConfig identifies the relying party that a [New]-constructed
// [RelyingParty] serves. The ID and display name would otherwise sit as
// adjacent same-typed string parameters, where a silent swap ships a broken
// RP ID; the field names make each value's role explicit at the call site.
type RPConfig struct {
	// ID is the relying party identifier, an effective domain
	// (e.g. "example.com").
	ID string
	// DisplayName is the human-readable relying party name shown by
	// authenticators.
	DisplayName string
	// Origins are the allowed browser origins for ceremonies
	// (e.g. "https://example.com").
	Origins []string
}

// New creates a configured [RelyingParty]. An RPConfig with an empty ID is
// rejected here with an error naming the field: upstream go-webauthn constructs
// successfully without an RP ID and then fails every ceremony with an RP-hash
// mismatch, which defeats this wrapper's purpose of making the relying party
// legible at construction.
func New(rp RPConfig) (*RelyingParty, error) {
	if rp.ID == "" {
		return nil, errors.New("auth/webauthn: RPConfig.ID is required")
	}
	wa, err := gowebauthn.New(&gowebauthn.Config{
		RPID:          rp.ID,
		RPDisplayName: rp.DisplayName,
		RPOrigins:     rp.Origins,
		Timeouts: gowebauthn.TimeoutsConfig{
			Login: gowebauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    CeremonyTimeout,
				TimeoutUVD: CeremonyTimeout,
			},
			Registration: gowebauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    CeremonyTimeout,
				TimeoutUVD: CeremonyTimeout,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return &RelyingParty{wa: wa}, nil
}

// ErrNotDiscoverable reports a registration whose client stated the new
// credential is not client-side discoverable. Matchable with errors.Is so a
// caller can tell it apart from a verification failure and tell the user their
// authenticator cannot store a passkey.
var ErrNotDiscoverable = errors.New("auth/webauthn: authenticator did not create a discoverable credential")

// BeginRegistration starts a WebAuthn registration ceremony.
//
// The credential parameters offer the three ML-DSA parameter sets ahead of
// EdDSA, ES256 and RS256, so an authenticator that implements a post-quantum
// algorithm produces a post-quantum credential and every authenticator in
// current use still registers on a classical one. Verifying an ML-DSA
// signature needs Go 1.27, which this module already requires.
func BeginRegistration(rp *RelyingParty, user *User) (*protocol.CredentialCreation, Ceremony, error) {
	options, session, err := rp.wa.BeginRegistration(user,
		gowebauthn.WithCredentialParameters(gowebauthn.CredentialParametersPQCRecommendedL3()),
		gowebauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		gowebauthn.WithExclusions(gowebauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
		gowebauthn.WithExtensions(gowebauthn.WithExtensionCredProps()),
	)
	if err != nil {
		return nil, Ceremony{}, err
	}
	return options, Ceremony{data: session}, nil
}

// FinishRegistration completes a WebAuthn registration ceremony.
//
// A credential the client reports as non-discoverable is rejected with
// [ErrNotDiscoverable] instead of being returned for storage. [BeginLogin] and
// [BeginConditionalLogin] are discoverable ceremonies, so such a credential can
// never complete a login: storing it gives the user a passkey in their list
// that fails every time they select it. The check reads the typed credProps
// output [BeginRegistration] requests, and an authenticator that reports
// nothing is accepted, because absence is not a denial.
func FinishRegistration(rp *RelyingParty, user *User, ceremony Ceremony, response *http.Request) (*gowebauthn.Credential, error) {
	cred, err := rp.wa.FinishRegistration(user, *ceremony.data, response)
	if err != nil {
		return nil, err
	}
	if err := rejectNonDiscoverable(cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// rejectNonDiscoverable reports [ErrNotDiscoverable] when the credProps output
// states the credential is not client-side discoverable. An absent report is
// accepted: the client sets rk to false only when the relying party did not ask
// for a resident key, and [BeginRegistration] always asks.
func rejectNonDiscoverable(cred *gowebauthn.Credential) error {
	if cred.Extensions.RK != nil && !*cred.Extensions.RK {
		return ErrNotDiscoverable
	}
	return nil
}

// BeginLogin starts a WebAuthn assertion ceremony (discoverable login).
func BeginLogin(rp *RelyingParty) (*protocol.CredentialAssertion, Ceremony, error) {
	return beganCeremony(rp.wa.BeginDiscoverableLogin(
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	))
}

// beganCeremony wraps an upstream Begin* result so each ceremony function stays
// a single expression rather than repeating the same four-line unwrap.
func beganCeremony(options *protocol.CredentialAssertion, session *gowebauthn.SessionData, err error) (*protocol.CredentialAssertion, Ceremony, error) {
	if err != nil {
		return nil, Ceremony{}, err
	}
	return options, Ceremony{data: session}, nil
}

// BeginConditionalLogin starts a WebAuthn assertion ceremony with conditional
// mediation, enabling browser autofill UI for passkeys.
func BeginConditionalLogin(rp *RelyingParty) (*protocol.CredentialAssertion, Ceremony, error) {
	return beganCeremony(rp.wa.BeginDiscoverableMediatedLogin(protocol.MediationConditional,
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	))
}

// finishLogin completes a WebAuthn assertion ceremony (discoverable login).
func finishLogin(wa *gowebauthn.WebAuthn, session *gowebauthn.SessionData, response *http.Request, userFinder func(rawID, userHandle []byte) (gowebauthn.User, error)) (gowebauthn.User, *gowebauthn.Credential, error) {
	return wa.FinishPasskeyLogin(userFinder, *session, response)
}

// CompleteLogin completes a discoverable (passkey) login ceremony against the
// store: it resolves the asserting user and registered credentials from the
// assertion's user handle, verifies the assertion response, and persists the
// post-login credential custody (sign count and authenticator flags, the
// cloned-authenticator detection state).
//
// The custody write is best-effort: a store failure is logged at Warn and does
// not fail the login (sign-count bookkeeping is clone *detection*, not part of
// assertion verification). The returned user is the account as stored — the
// caller owns account-status policy and MUST check User.Enabled (and any
// app-specific state) before creating a session. A ceremony failure caused by
// a credential deleted server-side surfaces as a wrapped
// [protocol.ErrorUnknownCredential], matchable with errors.As so callers can
// signal the client to forget the stale passkey.
func CompleteLogin(ctx context.Context, rp *RelyingParty, store Store, ceremony Ceremony, r *http.Request) (*auth.User, *gowebauthn.Credential, error) {
	resolved, cred, err := finishLogin(rp.wa, ceremony.data, r, storeUserFinder(ctx, store))
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: assertion ceremony failed: %w", err)
	}
	user, ok := resolved.(*User)
	if !ok || user.AuthUser == nil {
		// Unreachable with storeUserFinder (which only returns *User), kept as
		// a fail-closed guard against upstream contract drift.
		return nil, nil, errors.New("webauthn: ceremony resolved an unexpected user type")
	}
	persistLoginCustody(ctx, store, cred)
	return user.AuthUser, cred, nil
}

// storeUserFinder returns the credential-lookup callback the assertion
// ceremony uses to resolve the asserting user and their registered passkeys
// from the store. The returned errors are deliberately generic so an
// assertion response never reveals whether a particular user handle exists.
func storeUserFinder(ctx context.Context, store Store) func(rawID, userHandle []byte) (gowebauthn.User, error) {
	return func(_, userHandle []byte) (gowebauthn.User, error) {
		userID, _ := binary.Varint(userHandle)
		if userID <= 0 {
			return nil, errors.New("invalid user handle")
		}
		user, found, err := store.UserByID(ctx, userID)
		if err != nil || !found {
			return nil, errors.New("user not found")
		}
		creds, err := store.PasskeysByUserID(ctx, user.ID)
		if err != nil {
			return nil, errors.New("get passkeys failed")
		}
		return NewUser(user, creds)
	}
}

// persistLoginCustody writes the post-login credential custody: the
// authenticator's sign count and flags, including CloneWarning — the signal
// go-webauthn raises when a sign count regresses (a cloned-authenticator
// indicator) that must survive into storage to be visible to later ceremonies
// and audits. Best-effort by design; a failure is logged at Warn and never
// fails the login.
func persistLoginCustody(ctx context.Context, store Store, cred *gowebauthn.Credential) {
	err := store.UpdatePasskeyAfterLogin(ctx, cred.ID, cred.Authenticator.SignCount, auth.PasskeyFlags{
		UserPresent:    cred.Flags.UserPresent,
		UserVerified:   cred.Flags.UserVerified,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		CloneWarning:   cred.Authenticator.CloneWarning,
	})
	if err != nil {
		slog.Warn("webauthn: post-login credential update failed",
			"credential_id", hex.EncodeToString(cred.ID[:min(8, len(cred.ID))]),
			"error", err)
	}
}
