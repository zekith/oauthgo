package oauthgoreplay

import (
	"context"
	"sync"
	"time"
)

// MemoryReplayProtector backed by memory using a map.
type MemoryReplayProtector struct {
	mu   sync.Mutex
	seen map[string]int64 // key -> unix expiry
}

// NewMemoryReplayProtector creates a new MemoryReplayProtector.
func NewMemoryReplayProtector() *MemoryReplayProtector {
	return &MemoryReplayProtector{seen: make(map[string]int64)}
}

// FirstSeen returns true on first observation, false if seen before.
func (m *MemoryReplayProtector) FirstSeen(ctx context.Context, key string, ttl time.Duration) (bool, error) {

	// create current time and expiry time
	now := time.Now().Unix()
	exp := now + int64(ttl.Seconds())

	// lock so we don't have concurrent writes'
	m.mu.Lock()
	defer m.mu.Unlock()

	// cleanup expired entries
	m.cleanupExpiredEntries(now)

	// check if we've seen this key before'
	if _, ok := m.seen[key]; ok {
		return false, nil
	}

	// add the key to the seen map and return true
	m.seen[key] = exp
	return true, nil
}

// cleanupExpiredEntries removes expired entries from the seen map
func (m *MemoryReplayProtector) cleanupExpiredEntries(now int64) {

	// iterate over the map and remove expired entries
	for k, e := range m.seen {
		if e <= now {
			delete(m.seen, k)
		}
	}
}
