package oauthgodailymotion

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Dailymotion OAuth2 Provider Configuration
//
// Notes:
// - Dailymotion supports OAuth2 Authorization Code flow.
// - Refresh tokens are issued if requested.
// - User profile data is available at /me endpoint.
var dailymotionDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("dailymotion"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2 only, no OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://www.dailymotion.com/oauth/authorize"),
		TokenURL:      pointer.ToString("https://api.dailymotion.com/oauth/token"),
		RevocationURL: pointer.ToString("https://api.dailymotion.com/oauth/revoke"), // optional
		Scopes: pointer.To([]string{
			"read",
			"userinfo",
			"email",
			"manage_videos",
		}),
		UsePKCE: pointer.ToBool(true),
	},
	UserInfoURL: pointer.ToString("https://api.dailymotion.com/me"),
}

// NewWithOptions creates a new Dailymotion OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, dailymotionDefaults)
}

// GetUserInfoEndpoint returns Dailymotion's user profile endpoint
func GetUserInfoEndpoint() string {
	if dailymotionDefaults.UserInfoURL != nil {
		return *dailymotionDefaults.UserInfoURL
	}
	return ""
}
