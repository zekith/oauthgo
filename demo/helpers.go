package main

import (
	"strconv"

	"github.com/redis/go-redis/v9"
)

// NewRedisClient creates a new Redis client.
func NewRedisClient(addr, username, password, db string) *redis.Client {
	opt := &redis.Options{Addr: addr}
	if username != "" {
		opt.Username = username
	}
	if password != "" {
		opt.Password = password
	}
	if db != "" {
		if n, err := strconv.Atoi(db); err == nil {
			opt.DB = n
		}
	}
	return redis.NewClient(opt)
}
