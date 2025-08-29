package oauthgodiscord

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Discord
var discordDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("discord"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Discord supports OAuth2, not full OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://discord.com/api/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://discord.com/api/oauth2/token"),
		RevocationURL: pointer.ToString("https://discord.com/api/oauth2/token/revoke"),
		Scopes: pointer.To([]string{
			"identify", "email", // commonly used scopes
		}),
		UsePKCE: pointer.ToBool(true), // PKCE is supported and recommended
	},

	// Discord does not provide full OIDC metadata,
	// but we can mimic a userinfo endpoint using the API.
	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:           pointer.ToString("https://discord.com"),
		UserInfoURL:      pointer.ToString("https://discord.com/api/users/@me"),
		Scopes:           pointer.To([]string{"identify", "email"}),
		DisableDiscovery: pointer.ToBool(true),
	},
	UserInfoURL: pointer.ToString("https://discord.com/api/users/@me"),
}

// NewWithOptions creates a new Discord OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, discordDefaults)
}

// GetUserInfoEndpoint returns Discord's userinfo endpoint
func GetUserInfoEndpoint() string {
	if discordDefaults.UserInfoURL != nil {
		return *discordDefaults.UserInfoURL
	}
	return ""
}
