package oauthgoreplay

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisReplayProtector backed by Redis.
type RedisReplayProtector struct {
	Client *redis.Client
	Prefix string
}

// NewRedisReplayProtector creates a new RedisReplayProtector.
func NewRedisReplayProtector(client *redis.Client, prefix string) ReplayProtector {
	return &RedisReplayProtector{Client: client, Prefix: prefix}
}

// FirstSeen returns true on first observation, false if seen before.
func (r *RedisReplayProtector) FirstSeen(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	k := r.Prefix + key
	ok, err := r.Client.SetNX(ctx, k, "1", ttl).Result()
	if err != nil {
		return false, err
	}
	return ok, nil // ok==true -> first time set
}
