// Package store defines the composite store interface used by the
// authentication subsystem and implemented by persistence layers.
package store

import (
	"context"
	"time"

	"github.com/cplieger/auth"
)

// AuthStore is the composite store interface implemented by the
// concrete persistence layer and consumed by auth.
type AuthStore interface {
	UserStore
	SessionPersister
	PasskeyStore
	KeyStore
	OIDCStateStore
}

// UserStore persists user account data.
type UserStore interface {
	CreateUser(ctx context.Context, user *auth.User) error
	GetUserByID(ctx context.Context, id int64) (*auth.User, error)
	GetUserByUsername(ctx context.Context, username string) (*auth.User, error)
	GetUserByEmail(ctx context.Context, email string) (*auth.User, error)
	GetUserByOIDCSub(ctx context.Context, issuer, sub string) (*auth.User, error)
	ListUsers(ctx context.Context) ([]auth.User, error)
	UpdateUser(ctx context.Context, user *auth.User) error
	DeleteUser(ctx context.Context, id int64) error
	UserCount(ctx context.Context) (int, error)
}

// SessionPersister persists session data.
type SessionPersister interface {
	CreateSession(ctx context.Context, sess *auth.Session) error
	GetSessionByHash(ctx context.Context, tokenHash string) (*auth.Session, error)
	UpdateSessionActivity(ctx context.Context, tokenHash string, now time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID int64, exceptHash string) error
	CleanupExpiredSessions(ctx context.Context, now time.Time, idleTimeout, absTimeout time.Duration) (int64, error)
}

// PasskeyStore persists WebAuthn/FIDO2 credentials.
type PasskeyStore interface {
	CreatePasskey(ctx context.Context, cred *auth.PasskeyCredential) error
	GetPasskeysByUserID(ctx context.Context, userID int64) ([]auth.PasskeyCredential, error)
	GetPasskeyByCredentialID(ctx context.Context, credID []byte) (*auth.PasskeyCredential, error)
	UpdatePasskeyAfterLogin(ctx context.Context, credID []byte, signCount uint32, flags auth.PasskeyFlags) error
	RenamePasskey(ctx context.Context, id, userID int64, name string) error
	DeletePasskey(ctx context.Context, id, userID int64) error
	PasskeyCountForUser(ctx context.Context, userID int64) (int, error)
}

// KeyStore persists machine-to-machine API keys.
type KeyStore interface {
	CreateAPIKey(ctx context.Context, key *auth.Key) error
	GetAPIKeyByHash(ctx context.Context, hash string) (*auth.Key, error)
	ListAPIKeysByUserID(ctx context.Context, userID int64) ([]auth.Key, error)
	DeleteAPIKey(ctx context.Context, id, userID int64) error
}

// OIDCStateStore persists OIDC authentication state.
type OIDCStateStore interface {
	CreateOIDCState(ctx context.Context, state, nonce, codeVerifier, redirectURI string) error
	ConsumeOIDCState(ctx context.Context, state string) (nonce, codeVerifier, redirectURI string, err error)
	CleanupExpiredOIDCStates(ctx context.Context, now time.Time, maxAge time.Duration) (int64, error)
}
