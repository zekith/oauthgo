package oauthgozoom

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2 defaults for Zoom
var zoomDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("zoom"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Zoom supports OAuth2, not OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://zoom.us/oauth/authorize"),
		TokenURL:      pointer.ToString("https://zoom.us/oauth/token"),
		RevocationURL: pointer.ToString("https://zoom.us/oauth/revoke"),
		Scopes:        pointer.To([]string{}),
		UsePKCE:       pointer.ToBool(true), // PKCE is supported and recommended
	},
	UserInfoURL: pointer.ToString("https://api.zoom.us/v2/users/me"),
}

// NewWithOptions creates a new Zoom OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, zoomDefaults)
}

// GetUserInfoEndpoint returns Zoom's user info endpoint (/v2/users/me)
func GetUserInfoEndpoint() string {
	if zoomDefaults.UserInfoURL != nil {
		return *zoomDefaults.UserInfoURL
	}
	return ""
}
