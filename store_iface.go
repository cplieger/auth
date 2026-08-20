package auth

import (
	"context"
	"time"
)

// --- Session storage (role-split per OWASP ASVS L2 §3.3.3/3.3.4) ---
//
// Every by-key lookup below reports absence through a `found` result rather
// than a nil value with a nil error; the full contract, shared with the role
// interfaces of the persistence SPI, is documented once in store_contract.go.

// SessionReader finds session data by token hash.
type SessionReader interface {
	SessionByHash(ctx context.Context, tokenHash string) (sess *Session, found bool, err error)
}

// SessionWriter persists and removes session data.
type SessionWriter interface {
	CreateSession(ctx context.Context, sess *Session) error
	UpdateSessionActivity(ctx context.Context, tokenHash string, now time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID int64, exceptHash string) error
}

// SessionActivityUpdater updates the last activity timestamp for a session.
type SessionActivityUpdater interface {
	UpdateSessionActivity(ctx context.Context, tokenHash string, now time.Time) error
}

// SessionStore composes read + write for middleware that needs both.
type SessionStore interface {
	SessionReader
	SessionWriter
}

// --- User storage ---

// UserReader retrieves user records for authentication.
type UserReader interface {
	UserByID(ctx context.Context, id int64) (user *User, found bool, err error)
}

// --- API Key storage ---

// APIKeyReader validates API keys (looked up by hash).
type APIKeyReader interface {
	APIKeyByHash(ctx context.Context, hash string) (key *Key, found bool, err error)
}
