package oauthgoutils

import (
	"os"
)

// Get by default.
func Get(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
