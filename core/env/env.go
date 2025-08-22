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
		parseEnvLine(ln)
	}
	return nil
}

// parseEnvLine parses a single line from .env file and sets the environment variable if valid.
func parseEnvLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return
	}
	_ = os.Setenv(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
}
