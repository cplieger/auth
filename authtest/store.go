// Package authtest provides an in-memory implementation of [auth.AuthStore]
// for use in consumer tests. It is not intended for production use.
package authtest

import (
	"context"
	"sync"
	"time"

	"github.com/cplieger/auth"
)

// MemStore is an in-memory implementation of auth interfaces for testing.
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

// GetSessionByHash returns the session stored under tokenHash, or (nil, nil)
// if no such session exists.
func (m *MemStore) GetSessionByHash(_ context.Context, tokenHash string) (*auth.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenHash]
	if !ok {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}

// GetUserByID returns the user with the given id, or (nil, nil) if absent.
func (m *MemStore) GetUserByID(_ context.Context, id int64) (*auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	cp := *u
	return &cp, nil
}

// GetAPIKeyByHash returns the API key stored under hash, or (nil, nil) if absent.
func (m *MemStore) GetAPIKeyByHash(_ context.Context, hash string) (*auth.Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[hash]
	if !ok {
		return nil, nil
	}
	cp := *k
	return &cp, nil
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
	cp := *s
	m.sessions[cp.TokenHash] = &cp
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

// AddUser adds a user to the store and assigns an auto-incremented ID.
func (m *MemStore) AddUser(u *auth.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u.ID = m.nextID
	m.nextID++
	cp := *u
	m.users[cp.ID] = &cp
}

// AddSession adds a session to the store.
func (m *MemStore) AddSession(s *auth.Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *s
	m.sessions[cp.TokenHash] = &cp
}

// AddAPIKey adds an API key to the store.
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
