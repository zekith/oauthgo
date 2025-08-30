package oauthgotumblr

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

var tumblrDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("tumblr"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2 only, no OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://www.tumblr.com/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://api.tumblr.com/v2/oauth2/token"),
		RevocationURL: nil, // Not supported by Tumblr
		Scopes: pointer.To([]string{
			"basic", "write", "offline_access",
		}),
		UsePKCE: pointer.ToBool(true), // PKCE recommended for security
	},
	UserInfoURL: pointer.ToString("https://api.tumblr.com/v2/user/info"),
}

// NewWithOptions creates a new Tumblr OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, tumblrDefaults)
}

// GetUserInfoEndpoint returns Tumblr's user info endpoint
func GetUserInfoEndpoint() string {
	if tumblrDefaults.UserInfoURL != nil {
		return *tumblrDefaults.UserInfoURL
	}
	return ""
}
