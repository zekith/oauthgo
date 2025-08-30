package oauthgoasana

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Asana
var asanaDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("asana"),
	Mode: pointer.To(oauthgotypes.OIDC),

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://app.asana.com/-/oauth_authorize"),
		TokenURL:      pointer.ToString("https://app.asana.com/-/oauth_token"),
		RevocationURL: nil, // Asana does not expose a standard revocation endpoint
		Scopes:        pointer.To([]string{"openid", "profile", "email"}),
		UsePKCE:       pointer.ToBool(true),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://app.asana.com/api/1.0"),
		UserInfoURL: pointer.ToString("https://app.asana.com/api/1.0/openid_connect/userinfo"),
		Scopes:      pointer.To([]string{"openid", "profile", "email"}),
		JWKSURL:     pointer.ToString("https://app.asana.com/api/1.0/openid_connect/jwks"),
	},
}

// NewWithOptions creates a new Asana OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, asanaDefaults)
}

// GetUserInfoEndpoint returns Asana's user info endpoint (/users/me)
func GetUserInfoEndpoint() string {
	if asanaDefaults.OIDC.UserInfoURL != nil {
		return *asanaDefaults.OIDC.UserInfoURL
	}
	return ""
}
