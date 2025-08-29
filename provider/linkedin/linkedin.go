package oauthgolinkedin

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

// OAuthO2IDCProvider defaults for LinkedIn
var linkedInDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("linkedin"),
	Mode: pointer.To(oauthgotypes.OIDC),

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://www.linkedin.com/oauth/v2/authorization"),
		TokenURL:      pointer.ToString("https://www.linkedin.com/oauth/v2/accessToken"),
		RevocationURL: pointer.ToString("https://www.linkedin.com/oauth/v2/revoke"),
		Scopes:        pointer.To([]string{"email"}), // choose minimal OAuth2 default
		UsePKCE:       pointer.ToBool(false),         // PKCE is not supported for LinkedIn yet in this library as special handling is required
	},
	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:           pointer.ToString("https://www.linkedin.com/oauth"),
		JWKSURL:          pointer.ToString("https://www.linkedin.com/oauth/openid/jwks"),
		UserInfoURL:      pointer.ToString("https://api.linkedin.com/v2/userinfo"),
		Scopes:           pointer.To([]string{"openid", "profile", "email"}),
		DisableDiscovery: pointer.ToBool(true), // LinkedIn OIDC path is discovery-less
	},
}

func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, linkedInDefaults)
}

func GetUserInfoEndpoint() string {
	if linkedInDefaults.OIDC != nil && linkedInDefaults.OIDC.UserInfoURL != nil {
		return *linkedInDefaults.OIDC.UserInfoURL
	}
	return ""
}
