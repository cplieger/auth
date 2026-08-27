package webauthn

// The WebAuthn Signal API payloads (WebAuthn §5.1.10 and §5.1.11). A relying
// party sends these so a credential manager's stored passkey list stays in step
// with the server: which credentials are still accepted, and what the account is
// currently called. Without them a deleted passkey lingers in the user's list
// and a renamed account shows its old name forever.
//
// This package derives the payloads; delivering them is the client's job, since
// only the browser can call PublicKeyCredential.signalAllAcceptedCredentials and
// signalCurrentUserDetails.

// SignalAllAcceptedCredentials is the payload for the client's
// signalAllAcceptedCredentials call: every credential this relying party still
// accepts for the user.
//
// An EMPTY list is meaningful and is not the same as sending nothing — it tells
// the credential manager to remove every passkey it holds for this account,
// which is the correct signal after the last one is deleted server-side. It
// therefore always serializes as a JSON array, never as null.
type SignalAllAcceptedCredentials struct {
	RPID                     string      `json:"rpId"`
	UserID                   Base64URL   `json:"userId"`
	AllAcceptedCredentialIDs []Base64URL `json:"allAcceptedCredentialIds"`
}

// SignalCurrentUserDetails is the payload for the client's
// signalCurrentUserDetails call: what the account is called now.
type SignalCurrentUserDetails struct {
	RPID        string    `json:"rpId"`
	Name        string    `json:"name"`
	DisplayName string    `json:"displayName"`
	UserID      Base64URL `json:"userId"`
}

// Signals carries both reconciliation payloads for one user, derived together
// because both are read from the same account state and a client that sends one
// wants the other.
type Signals struct {
	CurrentUserDetails     SignalCurrentUserDetails     `json:"currentUserDetails"`
	AllAcceptedCredentials SignalAllAcceptedCredentials `json:"allAcceptedCredentials"`
}

// NewSignals derives both reconciliation payloads from a user and their stored
// credentials. It is pure and cannot fail: every value is read from the user, so
// there is no lookup to go wrong.
//
// The display name falls back to the username when the account has none, which
// matches what registration put in the credential in the first place, so the
// signal does not blank a name the authenticator is already showing.
func NewSignals(rpID string, user *User) Signals {
	handle := Base64URL(user.WebAuthnID())

	// Never nil: an empty list is a real instruction, so it has to reach the
	// client as [] rather than null.
	ids := make([]Base64URL, 0, len(user.Credentials))
	for i := range user.Credentials {
		ids = append(ids, Base64URL(user.Credentials[i].CredentialID))
	}

	return Signals{
		AllAcceptedCredentials: SignalAllAcceptedCredentials{
			RPID:                     rpID,
			UserID:                   handle,
			AllAcceptedCredentialIDs: ids,
		},
		CurrentUserDetails: SignalCurrentUserDetails{
			RPID:        rpID,
			UserID:      handle,
			Name:        user.WebAuthnName(),
			DisplayName: user.WebAuthnDisplayName(),
		},
	}
}
