package oauthgoenv

import (
	"os"
	"strings"
)

// Get by default.
func Get(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// LoadDotEnv loads key=value pairs from .env if present (no error if missing).
func LoadDotEnv() error {
	b, err := os.ReadFile(".env")
	if err != nil {
		return nil
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.SplitN(ln, "=", 2)
		if len(parts) != 2 {
			continue
		}
		_ = os.Setenv(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	return nil
}
