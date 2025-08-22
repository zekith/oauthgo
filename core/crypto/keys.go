package oauthgocrypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseECKey parses PKCS8 or EC private key from PEM bytes.
func ParseECKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}

	if key, err := parsePKCS8ECKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := parseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("not an ECDSA key or unsupported format")
}

// parsePKCS8ECKey attempts to parse the bytes as a PKCS8 private key and convert to ECDSA.
func parsePKCS8ECKey(keyBytes []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key")
	}

	return key, nil
}

// parseECPrivateKey attempts to parse the bytes as an EC private key.
func parseECPrivateKey(keyBytes []byte) (*ecdsa.PrivateKey, error) {
	return x509.ParseECPrivateKey(keyBytes)
}
