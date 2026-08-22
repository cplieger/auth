package auth

import (
	"context"
	"time"
)

// This file names the published implement-me SPI for the consumer-built
// handler layer: the complete persistence surface — users, sessions,
// passkeys, API keys, and OIDC state — that a consumer's storage layer
// implements and its HTTP handlers call. The auth library's own mechanisms
// consume only the narrow verifier interfaces (see store_iface.go); the role
// interfaces here mirror the library's ceremonies (UserByOIDCSub is the lookup
// a consumer runs to fill oidc.ResolveUser's existingBySub parameter, since
// ResolveUser maps claims onto a user the caller already fetched and performs
// no lookup itself; UpdatePasskeyAfterLogin is the post-login credential
// custody; ConsumeOIDCState encodes single-use state), so a storage layer
// implementing them end to end is equipped for every library flow. That last
// clause is a claim about what the consumer can then build, not a call-site
// test: most members here have no caller inside this library, and a member
// earns its place by being the store leg of a flow the library documents.
// Consumers needing less implement only the roles they use.
//
// A by-key lookup reports absence through its second result, never through a
// nil value with a nil error. Absence is a normal answer, not a failure, so it
// does not travel as an error — but it must be impossible to overlook, and a
// caller cannot reach the value without also receiving `found`. This mirrors
// the language's own map-lookup shape (`v, ok := m[k]`), which is the reflex a
// Go reader already has. A lookup that returned only (*T, error) would pass the
// habitual `if err != nil` check while handing back nothing, which is how a nil
// dereference reaches production. Contrast the List/Get*By<Parent> methods,
// which are SEARCHES: an empty slice with a nil error is the correct answer
// there and no `found` result is warranted. The narrow verifier interfaces in
// store_iface.go declare this same contract.
//
// OWNERSHIP: a lookup returns a value the CALLER owns. An implementation must
// not hand back a pointer it goes on to mutate, and must not read a pointer the
// caller passed to a write method after that method returns. Both halves are
// load-bearing rather than stylistic. This library reads a returned *Session
// after the lookup — [ValidateSession] reads LastActivity, and
// UpdateSessionActivity writes it — and two concurrent verifications of the
// same session run those against each other, so a store that returns an alias
// to state it keeps mutating creates a data race inside the caller, which no
// amount of locking inside the store can fix. A store that scans each query
// into a fresh value satisfies this for free, which is why a SQL-backed
// implementation cannot get it wrong; an in-memory or caching implementation
// must copy explicitly. [github.com/cplieger/auth/v4/authtest.MemStore] is the
// worked example, and its TestMemStoreIsolatesStoredValues is the shape of test
// that pins it.

// UserStore persists user account data.
type UserStore interface {
	CreateUser(ctx context.Context, user *User) error
	UserByID(ctx context.Context, id int64) (user *User, found bool, err error)
	UserByUsername(ctx context.Context, username string) (u *User, found bool, err error)
	UserByEmail(ctx context.Context, email string) (user *User, found bool, err error)
	UserByOIDCSub(ctx context.Context, issuer, sub string) (user *User, found bool, err error)
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id int64) error
	UserCount(ctx context.Context) (int, error)
}

// SessionPersister persists session data.
type SessionPersister interface {
	CreateSession(ctx context.Context, sess *Session) error
	SessionByHash(ctx context.Context, tokenHash string) (sess *Session, found bool, err error)
	UpdateSessionActivity(ctx context.Context, tokenHash string, now time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID int64, exceptHash string) error
	CleanupExpiredSessions(ctx context.Context, now time.Time, timeouts SessionTimeouts) (int64, error)
}

// PasskeyStore persists WebAuthn/FIDO2 credentials.
type PasskeyStore interface {
	CreatePasskey(ctx context.Context, cred *PasskeyCredential) error
	PasskeysByUserID(ctx context.Context, userID int64) ([]PasskeyCredential, error)
	PasskeyByCredentialID(ctx context.Context, credID []byte) (cred *PasskeyCredential, found bool, err error)
	UpdatePasskeyAfterLogin(ctx context.Context, credID []byte, signCount uint32, flags PasskeyFlags) error
	RenamePasskey(ctx context.Context, ref PasskeyRef, name string) error
	DeletePasskey(ctx context.Context, ref PasskeyRef) error
	PasskeyCountForUser(ctx context.Context, userID int64) (int, error)
}

// KeyStore persists machine-to-machine API keys.
type KeyStore interface {
	CreateAPIKey(ctx context.Context, key *Key) error
	APIKeyByHash(ctx context.Context, hash string) (key *Key, found bool, err error)
	ListAPIKeysByUserID(ctx context.Context, userID int64) ([]Key, error)
	DeleteAPIKey(ctx context.Context, ref KeyRef) error
}

// OIDCState is the opaque single-use CSRF-binding state value minted by the
// oidc subpackage (as oidc.State, an alias of this type). It is typed so a
// hand-written store implementation cannot transpose it with the equally
// opaque nonce or code verifier: the three are indistinguishable strings, and
// a swap in a Scan or INSERT would silently disable the protection each one
// carries.
type OIDCState string

// OIDCNonce is the opaque single-use ID-token replay-protection nonce minted
// by the oidc subpackage (as oidc.Nonce, an alias of this type). See
// [OIDCState] for why the store vocabulary is typed.
type OIDCNonce string

// OIDCCodeVerifier is the opaque single-use PKCE code verifier minted by the
// oidc subpackage (as oidc.CodeVerifier, an alias of this type). See
// [OIDCState] for why the store vocabulary is typed.
type OIDCCodeVerifier string

// OIDCStateStore persists OIDC authentication state.
type OIDCStateStore interface {
	CreateOIDCState(ctx context.Context, state OIDCState, nonce OIDCNonce, codeVerifier OIDCCodeVerifier, redirectURI string) error
	ConsumeOIDCState(ctx context.Context, state OIDCState) (nonce OIDCNonce, codeVerifier OIDCCodeVerifier, redirectURI string, err error)
	CleanupExpiredOIDCStates(ctx context.Context, now time.Time, maxAge time.Duration) (int64, error)
}
