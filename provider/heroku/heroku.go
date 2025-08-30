package oauthgoheroku

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Heroku OAuth2 Provider Configuration
//
// Notes:
// - Heroku uses OAuth2 Authorization Code flow.
// - Refresh tokens are supported.
// - Account information is available at /account endpoint.
var herokuDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("heroku"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2 only, no OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://id.heroku.com/oauth/authorize"),
		TokenURL:      pointer.ToString("https://id.heroku.com/oauth/token"),
		RevocationURL: pointer.ToString("https://id.heroku.com/oauth/revoke"), // optional
		Scopes: pointer.To([]string{
			"global", // default scope for full access
		}),
		UsePKCE: pointer.ToBool(true),
	},
	UserInfoURL: pointer.ToString("https://api.heroku.com/account"),
}

// NewWithOptions creates a new Heroku OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, herokuDefaults)
}

// GetUserInfoEndpoint returns Heroku's account info endpoint
func GetUserInfoEndpoint() string {
	if herokuDefaults.UserInfoURL != nil {
		return *herokuDefaults.UserInfoURL
	}
	return ""
}
