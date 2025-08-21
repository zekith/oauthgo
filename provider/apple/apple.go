package oauthgoapple

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	coreoidc "github.com/zekith/oauthgo/core/oidc"
	"github.com/zekith/oauthgo/core/replay"
	"github.com/zekith/oauthgo/core/state"
)

type Config struct {
	TeamID     string
	KeyID      string
	ClientID   string            // Services ID (e.g., com.example.web)
	PrivateKey *ecdsa.PrivateKey // ES256 key
}

// New creates a new Apple provider wired through the generic OIDC provider.
// Uses standard OIDC discovery at https://appleid.apple.com/.well-known/openid-configuration.
// IMPORTANT: The Apple client secret (JWT) expires quickly; for long-lived servers,
// prefer regenerating it before each token request.
func New(state *oauthgostate.StateCodec, rp oauthgoreplay.ReplayProtector, httpClient *http.Client, cfg Config) (*coreoidc.OIDCProvider, error) {
	if cfg.TeamID == "" || cfg.KeyID == "" || cfg.ClientID == "" || cfg.PrivateKey == nil {
		return nil, fmt.Errorf("apple: missing required config (TeamID, KeyID, ClientID, PrivateKey)")
	}

	secret, err := clientSecret(cfg.TeamID, cfg.ClientID, cfg.KeyID, cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("apple: build client secret: %w", err)
	}

	return coreoidc.NewOIDCProvider(
		"apple",
		coreoidc.OIDCConfig{
			Issuer:       "https://appleid.apple.com",
			ClientID:     cfg.ClientID,
			ClientSecret: secret, // NOTE: rotates/exp.
			Scopes:       []string{"name", "email"},
			// Discovery is enabled (DisableDiscovery=false).
			// If you wanted discovery-less, you'd also set AuthURL, TokenURL, JWKS, etc.
		},
		state,
		rp,
		httpClient,
	)
}

// clientSecret builds the Apple client secret (JWT) per docs.
// Header: alg=ES256, kid=<KeyID>
// Claims: iss=<TeamID>, iat=now, exp=now+5m, aud="https://appleid.apple.com", sub=<ClientID>
func clientSecret(teamID, clientID, keyID string, privateKey *ecdsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": "https://appleid.apple.com",
		"sub": clientID,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = keyID
	return t.SignedString(privateKey)
}
