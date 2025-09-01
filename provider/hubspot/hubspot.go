package oauthgohubspot

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// HubSpot OAuth2 Provider Configuration
//
// Notes:
// - HubSpot supports OAuth2 Authorization Code with refresh tokens.
// - Required scope: "oauth" must always be included.
// - User/account info can be fetched via https://api.hubapi.com/oauth/v1/access-tokens/{access_token}
var hubspotDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("hubspot"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // HubSpot doesn't expose OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:  pointer.ToString("https://app.hubspot.com/oauth/authorize"),
		TokenURL: pointer.ToString("https://api.hubapi.com/oauth/v1/token"),
		// HubSpot doesn’t provide a standard revoke endpoint; you can unlink via APIs if needed
		Scopes: pointer.To([]string{
			"oauth", // mandatory
		}),
		UsePKCE: pointer.ToBool(true),
	},

	UserInfoURL: pointer.ToString("https://api.hubapi.com/oauth/v1/access-tokens"),
}

// NewWithOptions creates a new HubSpot OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, hubspotDefaults)
}

// GetUserInfoEndpoint returns HubSpot's user info endpoint
// Note: You must append the access token, e.g., /access-tokens/{token}
func GetUserInfoEndpoint() string {
	if hubspotDefaults.UserInfoURL != nil {
		return *hubspotDefaults.UserInfoURL
	}
	return ""
}
