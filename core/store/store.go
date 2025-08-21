package oauthgostore

import (
	"context"
	"time"
)

// SessionData is the data stored in the session store.
type SessionData struct {
	Provider     string
	Subject      string
	Email        string
	Name         string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
	CreatedAt    time.Time
}

// SessionStore is an interface for storing and retrieving sessions.
type SessionStore interface {
	Put(ctx context.Context, id string, data SessionData, ttl time.Duration) error
	Get(ctx context.Context, id string) (SessionData, bool, error)
	Del(ctx context.Context, id string) error
}
