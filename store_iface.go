package auth

import (
	"context"
	"time"
)

// --- Session storage (role-split per OWASP ASVS L2 §3.3.3/3.3.4) ---

// SessionReader finds session data by token hash.
type SessionReader interface {
	GetSessionByHash(ctx context.Context, tokenHash string) (*Session, error)
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
	GetUserByID(ctx context.Context, id int64) (*User, error)
}

// --- API Key storage ---

// APIKeyReader validates API keys (looked up by hash).
type APIKeyReader interface {
	GetAPIKeyByHash(ctx context.Context, hash string) (*Key, error)
}
