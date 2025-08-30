package oauthgotwitch

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2 defaults for Twitch
var twitchDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("twitch"),
	Mode: pointer.To(oauthgotypes.OIDC),

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://id.twitch.tv/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://id.twitch.tv/oauth2/token"),
		RevocationURL: pointer.ToString("https://id.twitch.tv/oauth2/revoke"),
		Scopes: pointer.To([]string{
			"openid",
		}),
		UsePKCE: pointer.ToBool(true), // Twitch supports PKCE
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://id.twitch.tv/oauth2"),
		UserInfoURL: pointer.ToString("https://id.twitch.tv/oauth2/userinfo"),
		Scopes:      pointer.To([]string{"openid"}),
		JWKSURL:     pointer.ToString("https://id.twitch.tv/oauth2/keys"),
	},
}

// NewWithOptions creates a new Twitch OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, twitchDefaults)
}

// GetUserInfoEndpoint returns Twitch's /helix/users endpoint
func GetUserInfoEndpoint() string {
	if twitchDefaults.OIDC.UserInfoURL != nil {
		return *twitchDefaults.OIDC.UserInfoURL
	}
	return ""
}
