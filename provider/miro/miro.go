package oauthgomiro

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Miro
var miroDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("miro"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Miro supports OAuth2, not full OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://miro.com/oauth/authorize"),
		TokenURL:      pointer.ToString("https://api.miro.com/v1/oauth/token"),
		RevocationURL: pointer.ToString("https://api.miro.com/v1/oauth/revoke"),
		Scopes: pointer.To([]string{
			"boards:read",
			"boards:write",
			"identity:read",
			"team:read",
		}),
		UsePKCE: pointer.ToBool(true),
	},
	UserInfoURL: pointer.ToString("https://api.miro.com/v1/users/me"),
}

// NewWithOptions creates a new Miro OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, miroDefaults)
}

// GetUserInfoEndpoint returns Miro's user info endpoint (/v1/users/me)
func GetUserInfoEndpoint() string {
	if miroDefaults.UserInfoURL != nil {
		return *miroDefaults.UserInfoURL
	}
	return ""
}
