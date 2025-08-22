package oauthgoutils

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomStringURLSafe returns a URL-safe base64 string (no padding).
func RandomStringURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MustRandom panics on error; for places where we already handle outer errors.
func MustRandom(n int) string {
	s, err := RandomStringURLSafe(n)
	if err != nil {
		panic(err)
	}
	return s
}
