package auth

import "context"

// SessionStore is the narrow interface consumed by [Authenticator].
// It declares only the store methods needed for session and API-key
// authentication, enabling focused testing with minimal fakes.
type SessionStore interface {
	GetSessionByHash(ctx context.Context, tokenHash string) (*Session, error)
	GetUserByID(ctx context.Context, id int64) (*User, error)
	GetAPIKeyByHash(ctx context.Context, hash string) (*Key, error)
}
