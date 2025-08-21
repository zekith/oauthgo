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
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if key, ok := k.(*ecdsa.PrivateKey); ok {
			return key, nil
		}
	}
	if k2, err2 := x509.ParseECPrivateKey(block.Bytes); err2 == nil {
		return k2, nil
	}
	return nil, fmt.Errorf("not an ECDSA key or unsupported format")
}
