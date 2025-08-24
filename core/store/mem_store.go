package oauthgostore

import (
	"context"
	"sync"
	"time"
)

// MemorySessionStore is a simple in-memory session store.
type MemorySessionStore struct {
	mu   sync.RWMutex
	vals map[string]SessionData
	exp  map[string]time.Time
}

// NewMemorySessionStore creates a new MemorySessionStore.
func NewMemorySessionStore() SessionStore {
	return &MemorySessionStore{vals: map[string]SessionData{}, exp: map[string]time.Time{}}
}

// Put stores a session in the store.
func (m *MemorySessionStore) Put(ctx context.Context, id string, data SessionData, ttl time.Duration) error {
	// Lock to prevent concurrent writes.
	m.mu.Lock()
	// Unlock before returning.
	defer m.mu.Unlock()
	// Store the session.
	m.vals[id] = data
	// Set the expiry time.
	m.exp[id] = time.Now().Add(ttl)
	return nil
}

// Get retrieves a session from the store.
func (m *MemorySessionStore) Get(ctx context.Context, id string) (SessionData, bool, error) {
	// Lock to prevent concurrent reads.
	m.mu.RLock()

	// Unlock before returning.
	defer m.mu.RUnlock()

	// Check if the session exists and hasn't expired.'
	exp, ok := m.exp[id]

	// If the session doesn't exist or has expired, return an empty session.'
	if !ok || time.Now().After(exp) {
		return SessionData{}, false, nil
	}

	// Return the session.
	v, ok := m.vals[id]

	return v, ok, nil
}

// Del deletes a session from the store.
func (m *MemorySessionStore) Del(ctx context.Context, id string) error {
	// Lock to prevent concurrent writes.
	m.mu.Lock()

	// Unlock before returning.
	defer m.mu.Unlock()

	// Delete the session.
	delete(m.vals, id)

	// Delete the expiry time.
	delete(m.exp, id)

	return nil
}
