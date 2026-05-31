package auth

import "context"

// WebAuthnStore is the narrow interface consumed by WebAuthn/passkey
// handlers. It declares only the store methods needed for passkey
// authentication, enabling focused testing with minimal fakes.
type WebAuthnStore interface {
	GetPasskeysByUserID(ctx context.Context, userID int64) ([]PasskeyCredential, error)
	UpdatePasskeyAfterLogin(ctx context.Context, credID []byte, signCount uint32, flags PasskeyFlags) error
	GetUserByID(ctx context.Context, id int64) (*User, error)
}
