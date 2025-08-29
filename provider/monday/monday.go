package oauthgomonday

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Monday.com
var mondayDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("monday"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Monday.com supports OAuth2, not OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://auth.monday.com/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://auth.monday.com/oauth2/token"),
		RevocationURL: nil, // Monday.com does not provide a standard revocation endpoint
		Scopes:        pointer.To([]string{"me:read"}),
		UsePKCE:       pointer.ToBool(true),
	},

	UserInfoURL: pointer.ToString("https://api.monday.com/v2"),
}

// NewWithOptions creates a new Monday.com OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, mondayDefaults)
}

// GetUserInfoEndpoint returns Monday.com's GraphQL endpoint (/v2) for user info
func GetUserInfoEndpoint() string {
	if mondayDefaults.UserInfoURL != nil {
		return *mondayDefaults.UserInfoURL
	}
	return ""
}
