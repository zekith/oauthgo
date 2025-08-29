package oauthgobox

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

var boxDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("box"),
	Mode: pointer.To(oauthgotypes.OIDC), // Box supports OpenID Connect

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://account.box.com/api/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://api.box.com/oauth2/token"),
		RevocationURL: pointer.ToString("https://api.box.com/oauth2/revoke"),
		Scopes: pointer.To([]string{
			"root_readwrite",
		}),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:                     pointer.ToString("https://account.box.com"),
		UserInfoURL:                pointer.ToString("https://api.box.com/2.0/users/me"),
		Scopes:                     pointer.To([]string{"root_readwrite"}),
		DisableIdTokenVerification: pointer.ToBool(true),
	},
}

// NewWithOptions creates a new Box OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, boxDefaults)
}

func GetUserInfoEndpoint() string {

	if boxDefaults.OIDC != nil && boxDefaults.OIDC.UserInfoURL != nil {
		return *boxDefaults.OIDC.UserInfoURL
	}
	return ""
}
