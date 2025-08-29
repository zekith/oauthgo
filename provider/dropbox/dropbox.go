package oauthgodropbox

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Dropbox
var dropboxDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("dropbox"),
	Mode: pointer.To(oauthgotypes.OIDC), // Dropbox supports OAuth2, not full OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://www.dropbox.com/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://api.dropboxapi.com/oauth2/token"),
		RevocationURL: pointer.ToString("https://api.dropboxapi.com/2/auth/token/revoke"),
		Scopes:        pointer.To([]string{}), // Dropbox typically does not require scope strings; access is defined by app perms
		UsePKCE:       pointer.ToBool(true),   // PKCE is supported and recommended
		ExtraAuth: pointer.To(map[string]string{
			"token_access_type": "offline", // request refresh tokens
		}),
	},
	OIDC: &oauthgotypes.OIDCOptions{
		Issuer: pointer.ToString("https://www.dropbox.com"),
		Scopes: pointer.To([]string{"openid", "profile", "email"}),
	},
	UserInfoURL: pointer.ToString("https://api.dropboxapi.com/2/openid/userinfo"),
}

// NewWithOptions creates a new Dropbox OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, dropboxDefaults)
}

// GetUserInfoEndpoint returns Dropbox's "get_current_account" endpoint
func GetUserInfoEndpoint() string {
	if dropboxDefaults.UserInfoURL != nil {
		return *dropboxDefaults.UserInfoURL
	}
	return ""
}
