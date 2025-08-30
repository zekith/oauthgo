package oauthgofitbit

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Fitbit OAuth2 Provider Configuration
//
// Notes:
// - Fitbit supports OAuth2 Authorization Code + PKCE.
// - User profile is retrieved via https://api.fitbit.com/1/user/-/profile.json
// - Refresh tokens are supported.
// - Requires "Server" app type in Fitbit Developer Portal.
var fitbitDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("fitbit"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Fitbit doesn’t expose OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://www.fitbit.com/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://api.fitbit.com/oauth2/token"),
		RevocationURL: pointer.ToString("https://api.fitbit.com/oauth2/revoke"),
		Scopes: pointer.To([]string{
			"profile",
			"activity",
			"sleep",
			"heartrate",
		}),
		UsePKCE: pointer.ToBool(true),
	},

	UserInfoURL: pointer.ToString("https://api.fitbit.com/1/user/-/profile.json"),
}

// NewWithOptions creates a new Fitbit OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, fitbitDefaults)
}

// GetUserInfoEndpoint returns Fitbit's user info endpoint
func GetUserInfoEndpoint() string {
	if fitbitDefaults.UserInfoURL != nil {
		return *fitbitDefaults.UserInfoURL
	}
	return ""
}
