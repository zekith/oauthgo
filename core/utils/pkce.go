package oauthgoutils

import (
	"crypto/sha256"
	"encoding/base64"
)

// PKCE is a Proof Key for Code Exchange (RFC 7636)
type PKCE struct {
	// Verifier is a random string used to prove the client is the same that requested the authorization code.
	Verifier string
	// Challenge is the code challenge.
	Challenge string
	// Method is the code challenge method.
	Method string // S256
}

// NewPKCE creates a new PKCE.
func NewPKCE() (*PKCE, error) {

	// Create a random verifier
	verifier, err := RandomStringURLSafe(32)
	if err != nil {
		return nil, err
	}

	// Hash the verifier
	s := sha256.Sum256([]byte(verifier))

	// Encode the hash verifier as a base64 string and use it as the challenge
	challenge := base64.RawURLEncoding.EncodeToString(s[:])

	// Return the PKCE with the verifier and challenge
	return &PKCE{Verifier: verifier, Challenge: challenge, Method: "S256"}, nil
}
