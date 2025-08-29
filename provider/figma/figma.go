package oauthgofigma

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Figma
var figmaDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("figma"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Figma supports OAuth2, not full OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://www.figma.com/oauth"),
		TokenURL:      pointer.ToString("https://api.figma.com/v1/oauth/token"),
		RevocationURL: nil, // Figma does not provide a standard revocation endpoint
		Scopes: pointer.To([]string{
			"files:read",
			"file_comments:read",
			"file_comments:write",
			"current_user:read",
		}),
		UsePKCE: pointer.ToBool(true),
	},

	UserInfoURL: pointer.ToString("https://api.figma.com/v1/me"),
}

// NewWithOptions creates a new Figma OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, figmaDefaults)
}

// GetUserInfoEndpoint returns Figma's user info endpoint (/v1/me)
func GetUserInfoEndpoint() string {
	if figmaDefaults.UserInfoURL != nil {
		return *figmaDefaults.UserInfoURL
	}
	return ""
}
