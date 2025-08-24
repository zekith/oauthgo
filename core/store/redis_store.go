package oauthgostore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisSessionStore is a session store that uses Redis.
type RedisSessionStore struct {
	Client *redis.Client
	Prefix string
}

// NewRedisSessionStore creates a new RedisSessionStore.
func NewRedisSessionStore(client *redis.Client, prefix string) SessionStore {
	return &RedisSessionStore{Client: client, Prefix: prefix}
}

// key returns the key for the given session ID.
func (s *RedisSessionStore) key(id string) string { return s.Prefix + id }

// Put stores a session in the store.
func (s *RedisSessionStore) Put(ctx context.Context, id string, data SessionData, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.Client.Set(ctx, s.key(id), b, ttl).Err()
}

// Get retrieves a session from the store.
func (s *RedisSessionStore) Get(ctx context.Context, id string) (SessionData, bool, error) {
	b, err := s.Client.Get(ctx, s.key(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return SessionData{}, false, nil
	}
	if err != nil {
		return SessionData{}, false, err
	}
	var d SessionData
	if err := json.Unmarshal(b, &d); err != nil {
		return SessionData{}, false, err
	}
	return d, true, nil
}

// Del deletes a session from the store.
func (s *RedisSessionStore) Del(ctx context.Context, id string) error {
	return s.Client.Del(ctx, s.key(id)).Err()
}
