package oauthgointercom

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

var intercomDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("intercom"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2 only

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://app.intercom.com/oauth"),
		TokenURL:      pointer.ToString("https://api.intercom.io/auth/eagle/token"),
		RevocationURL: nil, // Intercom does not provide RFC7009 revocation
		Scopes: pointer.To([]string{
			"read_users",
			"write_conversations",
		}),
		UsePKCE: pointer.ToBool(true), // PKCE is supported & recommended
	},

	UserInfoURL: pointer.ToString("https://api.intercom.io/me"),
}

// NewWithOptions creates a new Intercom OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, intercomDefaults)
}

// GetUserInfoEndpoint returns Intercom's /me endpoint
func GetUserInfoEndpoint() string {
	if intercomDefaults.UserInfoURL != nil {
		return *intercomDefaults.UserInfoURL
	}
	return ""
}
