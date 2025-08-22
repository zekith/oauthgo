package oauthgoreplay

import (
	"context"
	"time"
)

// ReplayProtector prevents state/nonce reuse. FirstSeen returns true on first observation, false if seen before.
type ReplayProtector interface {
	// FirstSeen returns true on first observation, false if seen before.
	FirstSeen(ctx context.Context, key string, ttl time.Duration) (bool, error)
}
