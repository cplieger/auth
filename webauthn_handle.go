package auth

import (
	"crypto/rand"
	"encoding/binary"
)

// WebAuthnHandleSize is the length of a generated user handle. WebAuthn caps a
// user handle at 64 bytes and §14.6.1 recommends using all of them, randomly.
const WebAuthnHandleSize = 64

// GenerateWebAuthnHandle returns a new WebAuthn user handle: 64 random bytes, as
// [WebAuthn §14.6.1] recommends.
//
// The handle identifies an account to an authenticator, and an authenticator may
// reveal it without verifying the user first, so it must carry no information
// about who the account belongs to. That rules out a username, an email address,
// and any unsalted hash of one — and it also rules out a sequential database
// identifier, which is not personally identifying but does leak how many accounts
// the relying party has and in what order they were created.
//
// Store the result on the account (see auth.User.WebAuthnHandle). The
// specification says to store it rather than derive it for a practical reason: a
// derived handle cannot be changed without invalidating every credential
// registered under the old derivation.
//
// It cannot fail; see [generateRandomHex] for why a randomness failure is not a
// reportable error in this library.
//
// [WebAuthn §14.6.1]: https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy
func GenerateWebAuthnHandle() []byte {
	b := make([]byte, WebAuthnHandleSize)
	rand.Read(b) // never returns an error (Go 1.24+); it crashes instead
	return b
}

// LegacyWebAuthnHandle returns the handle this library derived from a user ID
// before handles were stored: a binary varint of the row identifier.
//
// It exists for one job — backfilling auth.User.WebAuthnHandle for accounts that
// registered a passkey under the derived scheme. Those credentials are bound to
// this exact value, so writing it during the migration keeps every existing
// passkey working, where writing a fresh random handle would orphan all of them.
//
// Do not call it for a new account: use [GenerateWebAuthnHandle]. This derivation
// is the one §14.6.1 advises against, and it is kept only because the credentials
// already in the field were registered with it.
func LegacyWebAuthnHandle(userID int64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(buf, userID)
	return buf[:n]
}
