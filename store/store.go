// Package store defines the composite persistence contract for the
// authentication subsystem. It is the published implement-me SPI for the
// consumer-built handler layer: the auth library's own mechanisms consume only
// the narrow verifier interfaces (auth.SessionVerifierStore,
// auth.APIKeyVerifierStore), while this package names the complete surface —
// users, sessions, passkeys, API keys, and OIDC state — that a consumer's
// storage layer implements and its HTTP handlers call.
package store

import (
	"context"
	"time"

	"github.com/cplieger/auth/v3"
)

// Composite is the full persistence contract implemented by the consumer's
// storage layer. No auth library code consumes it: its method set mirrors the
// library's ceremonies (GetUserByOIDCSub is oidc.ResolveUser's lookup key,
// UpdatePasskeyAfterLogin is the post-login credential custody,
// ConsumeOIDCState encodes single-use state), so implementing it end-to-end
// equips a consumer's handler layer for every library flow. Consumers needing
// less implement the narrow role interfaces below instead.
type Composite interface {
	UserStore
	SessionPersister
	PasskeyStore
	KeyStore
	OIDCStateStore
}

// A by-key lookup reports absence through its second result, never through a
// nil value with a nil error. Absence is a normal answer, not a failure, so it
// does not travel as an error — but it must be impossible to overlook, and a
// caller cannot reach the value without also receiving `found`. This mirrors
// the language's own map-lookup shape (`v, ok := m[k]`), which is the reflex a
// Go reader already has. A lookup that returned only (*T, error) would pass the
// habitual `if err != nil` check while handing back nothing, which is how a nil
// dereference reaches production. Contrast the List/Get*By<Parent> methods,
// which are SEARCHES: an empty slice with a nil error is the correct answer
// there and no `found` result is warranted.

// UserStore persists user account data.
type UserStore interface {
	CreateUser(ctx context.Context, user *auth.User) error
	GetUserByID(ctx context.Context, id int64) (user *auth.User, found bool, err error)
	GetUserByUsername(ctx context.Context, username string) (u *auth.User, found bool, err error)
	GetUserByEmail(ctx context.Context, email string) (user *auth.User, found bool, err error)
	GetUserByOIDCSub(ctx context.Context, issuer, sub string) (user *auth.User, found bool, err error)
	ListUsers(ctx context.Context) ([]auth.User, error)
	UpdateUser(ctx context.Context, user *auth.User) error
	DeleteUser(ctx context.Context, id int64) error
	UserCount(ctx context.Context) (int, error)
}

// SessionPersister persists session data.
type SessionPersister interface {
	CreateSession(ctx context.Context, sess *auth.Session) error
	GetSessionByHash(ctx context.Context, tokenHash string) (sess *auth.Session, found bool, err error)
	UpdateSessionActivity(ctx context.Context, tokenHash string, now time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID int64, exceptHash string) error
	CleanupExpiredSessions(ctx context.Context, now time.Time, idleTimeout, absTimeout time.Duration) (int64, error)
}

// PasskeyStore persists WebAuthn/FIDO2 credentials.
type PasskeyStore interface {
	CreatePasskey(ctx context.Context, cred *auth.PasskeyCredential) error
	GetPasskeysByUserID(ctx context.Context, userID int64) ([]auth.PasskeyCredential, error)
	GetPasskeyByCredentialID(ctx context.Context, credID []byte) (cred *auth.PasskeyCredential, found bool, err error)
	UpdatePasskeyAfterLogin(ctx context.Context, credID []byte, signCount uint32, flags auth.PasskeyFlags) error
	RenamePasskey(ctx context.Context, id, userID int64, name string) error
	DeletePasskey(ctx context.Context, id, userID int64) error
	PasskeyCountForUser(ctx context.Context, userID int64) (int, error)
}

// KeyStore persists machine-to-machine API keys.
type KeyStore interface {
	CreateAPIKey(ctx context.Context, key *auth.Key) error
	GetAPIKeyByHash(ctx context.Context, hash string) (key *auth.Key, found bool, err error)
	ListAPIKeysByUserID(ctx context.Context, userID int64) ([]auth.Key, error)
	DeleteAPIKey(ctx context.Context, id, userID int64) error
}

// OIDCStateStore persists OIDC authentication state.
type OIDCStateStore interface {
	CreateOIDCState(ctx context.Context, state, nonce, codeVerifier, redirectURI string) error
	ConsumeOIDCState(ctx context.Context, state string) (nonce, codeVerifier, redirectURI string, err error)
	CleanupExpiredOIDCStates(ctx context.Context, now time.Time, maxAge time.Duration) (int64, error)
}
