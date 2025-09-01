package oauthgoapple

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateClientSecret generates a JWT client secret for Apple OAuth2
func GenerateClientSecret(teamID, clientID, keyID string, privateKeyPEM []byte) (string, error) {
	// Parse the private key
	key, err := jwt.ParseECPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}

	// Current and expiration time
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": teamID,                         // Apple Team ID
		"iat": now.Unix(),                     // Issued at
		"exp": now.Add(time.Hour * 24).Unix(), // Expiration (max 6 months, we use 24h here)
		"aud": "https://appleid.apple.com",
		"sub": clientID, // Service ID (Client ID)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID

	return token.SignedString(key)
}

// AppleIDClaims represents the ID token claims returned by Apple
type AppleIDClaims struct {
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	AuthTime      int64  `json:"auth_time"`
	Nonce         string `json:"nonce"`
	jwt.RegisteredClaims
}

// ParseIDToken decodes Apple's id_token without signature verification
// (Apple publishes JWKS, but often decoding for profile is enough).
func ParseIDToken(idToken string) (*AppleIDClaims, error) {
	claims := &AppleIDClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(idToken, claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// LoadPrivateKey loads the private key from a .p8 file
func LoadPrivateKey(path string) ([]byte, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read .p8 file: %w", err)
	}
	return keyBytes, nil
}
