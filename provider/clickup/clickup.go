package oauthgoclickup

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for ClickUp
var clickupDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("clickup"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // ClickUp supports OAuth2, not OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		// OAuth2 endpoints
		AuthURL:       pointer.ToString("https://app.clickup.com/api"),
		TokenURL:      pointer.ToString("https://api.clickup.com/api/v2/oauth/token"),
		RevocationURL: nil,                    // ClickUp does not provide a standard revocation endpoint
		Scopes:        pointer.To([]string{}), // ClickUp doesn’t use scopes; permissions are tied to the app
		UsePKCE:       pointer.ToBool(true),   // PKCE is supported
	},
	UserInfoURL: pointer.ToString("https://api.clickup.com/api/v2/user"),
}

// NewWithOptions creates a new ClickUp OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, clickupDefaults)
}

// GetUserInfoEndpoint returns ClickUp's /user endpoint
func GetUserInfoEndpoint() string {
	if clickupDefaults.UserInfoURL != nil {
		return *clickupDefaults.UserInfoURL
	}
	return ""
}
