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
	now := time.Now().Unix()
	exp := now + int64(ttl.Seconds())
	m.mu.Lock()
	defer m.mu.Unlock()
	// cleanup lazily
	for k, e := range m.seen {
		if e <= now {
			delete(m.seen, k)
		}
	}
	if _, ok := m.seen[key]; ok {
		return false, nil
	}
	m.seen[key] = exp
	return true, nil
}
