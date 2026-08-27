package auth

import (
	"context"
	"time"
)

// --- Session storage (role-split per OWASP ASVS L2 §3.3.3/3.3.4) ---
//
// Every by-key lookup below reports absence through a `found` result rather
// than a nil value with a nil error, and returns a value the CALLER owns. Both
// halves of the contract, shared with the role interfaces of the persistence
// SPI, are documented once in store_contract.go. The ownership half is what
// makes concurrent verification of one session safe: [SessionVerifier.Verify]
// reads the returned session after the lookup while a sibling verification may
// be calling UpdateSessionActivity, so a store returning an alias to state it
// mutates races inside this library.

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

// SessionStore is the session read+write set [github.com/cplieger/auth/v5/authtest.MemStore]
// implements. No mechanism in this library consumes it: the library calls only
// SessionByHash and UpdateSessionActivity (see [AuthenticatorStore]), and a
// consumer's handler layer implements [SessionPersister] or declares the narrow
// interface it actually calls. Scheduled for removal in v5.
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
