// Package authtest provides an in-memory implementation of [auth.AuthenticatorStore]
// for use in consumer tests. It is not intended for production use.
//
// Every read returns a fresh copy and every write stores a fresh copy, so a
// consumer test can mutate what it receives without reaching the store's state
// and vice versa. That isolation is what [TestMemStoreIsolatesStoredValues]
// pins: it holds today because [auth.User], [auth.Session] and [auth.Key]
// contain no pointer, slice or map field, so a struct copy is a complete one.
// A reference-typed field added to any of the three would silently break it,
// which is why the guarantee is asserted rather than assumed.
package authtest

import (
	"context"
	"sync"
	"time"

	"github.com/cplieger/auth/v5"
)

// MemStore is an in-memory implementation of auth interfaces for testing.
// A MemStore must be constructed with [NewMemStore]: the zero value has nil
// maps and panics on the first Add/Create call.
type MemStore struct {
	users    map[int64]*auth.User
	sessions map[string]*auth.Session
	apiKeys  map[string]*auth.Key
	nextID   int64
	mu       sync.Mutex
}

// NewMemStore returns a new empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{
		users:    make(map[int64]*auth.User),
		sessions: make(map[string]*auth.Session),
		apiKeys:  make(map[string]*auth.Key),
		nextID:   1,
	}
}

// SessionByHash returns a copy of the session stored under tokenHash. found is
// false when no such session exists; err is always nil.
func (m *MemStore) SessionByHash(_ context.Context, tokenHash string) (sess *auth.Session, found bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenHash]
	if !ok {
		return nil, false, nil
	}
	return new(*s), true, nil
}

// UserByID returns a copy of the user with the given id. found is false when
// the user is absent; err is always nil.
func (m *MemStore) UserByID(_ context.Context, id int64) (user *auth.User, found bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, false, nil
	}
	return new(*u), true, nil
}

// APIKeyByHash returns a copy of the API key stored under hash. found is false
// when the key is absent; err is always nil.
func (m *MemStore) APIKeyByHash(_ context.Context, hash string) (key *auth.Key, found bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[hash]
	if !ok {
		return nil, false, nil
	}
	return new(*k), true, nil
}

// UpdateSessionActivity sets LastActivity to now for the session identified by
// tokenHash. It is a no-op if no such session exists.
func (m *MemStore) UpdateSessionActivity(_ context.Context, tokenHash string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[tokenHash]; ok {
		s.LastActivity = now
	}
	return nil
}

// CreateSession stores a copy of s, keyed by its TokenHash.
func (m *MemStore) CreateSession(_ context.Context, s *auth.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.TokenHash] = new(*s)
	return nil
}

// DeleteSession removes the session stored under tokenHash, if any.
func (m *MemStore) DeleteSession(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, tokenHash)
	return nil
}

// DeleteUserSessions removes every session belonging to userID except the one
// whose token hash equals exceptHash.
func (m *MemStore) DeleteUserSessions(_ context.Context, userID int64, exceptHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, s := range m.sessions {
		if s.UserID == userID && hash != exceptHash {
			delete(m.sessions, hash)
		}
	}
	return nil
}

// AddUser stores a copy of u and assigns it an auto-incremented ID, which it
// also writes back to u so the caller knows the ID its user was given.
func (m *MemStore) AddUser(u *auth.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u.ID = m.nextID
	m.nextID++
	m.users[u.ID] = new(*u)
}

// AddSession stores a copy of s, keyed by its TokenHash.
func (m *MemStore) AddSession(s *auth.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.TokenHash] = new(*s)
}

// AddAPIKey stores a copy of k, keyed by its KeyHash, assigning an
// auto-incremented ID when k carries none. Unlike [MemStore.AddUser] it does
// not write the ID back: k.ID == 0 is how a caller asks for one, so writing it
// back would change the meaning of a second Add of the same value.
func (m *MemStore) AddAPIKey(k *auth.Key) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *k
	if cp.ID == 0 {
		cp.ID = m.nextID
		m.nextID++
	}
	m.apiKeys[cp.KeyHash] = &cp
}
