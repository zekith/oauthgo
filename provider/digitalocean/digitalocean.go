package oauthgodigitalocean

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

// OAuth2 defaults for DigitalOcean
//
//	support OAuth 2.0 (authorization code with refresh tokens) but do not provide OIDC discovery/ID tokens.
//
// Use the /v2/account endpoint to retrieve the current account profile.
var digitalOceanDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("digitalocean"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2-only (no OIDC/JWKS)

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://cloud.digitalocean.com/v1/oauth/authorize"),
		TokenURL:      pointer.ToString("https://cloud.digitalocean.com/v1/oauth/token"),
		RevocationURL: nil, // DigitalOcean does not expose an RFC7009 revocation endpoint
		Scopes: pointer.To([]string{
			"read",
			"write",
		}), // DO scopes are typically "read" and/or "write"
		UsePKCE: pointer.ToBool(true), // PKCE is supported/recommended
	},

	// No OIDC section for DigitalOcean
	OIDC: nil,

	// DigitalOcean "userinfo" equivalent
	UserInfoURL: pointer.ToString("https://api.digitalocean.com/v2/account"),
}

// NewWithOptions creates a new DigitalOcean OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, digitalOceanDefaults)
}

// GetUserInfoEndpoint returns DigitalOcean's account endpoint
func GetUserInfoEndpoint() string {
	if digitalOceanDefaults.UserInfoURL != nil {
		return *digitalOceanDefaults.UserInfoURL
	}
	return ""
}
