package oauthgoyahoo

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Yahoo OAuth2/OIDC Provider Configuration
//
// Notes:
// - Yahoo supports OAuth2 + OpenID Connect.
// - Refresh tokens are issued if "offline_access" or "openid" scope is included.
// - User profile data is available at /openid/v1/userinfo.
var yahooDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("yahoo"),
	Mode: pointer.To(oauthgotypes.OIDC), // Yahoo supports OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://api.login.yahoo.com/oauth2/request_auth"),
		TokenURL:      pointer.ToString("https://api.login.yahoo.com/oauth2/get_token"),
		RevocationURL: pointer.ToString("https://api.login.yahoo.com/oauth2/revoke"),
		Scopes: pointer.To([]string{
			"openid",
			"profile",
			"email",
		}),
		UsePKCE: pointer.ToBool(true),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://api.login.yahoo.com"),
		UserInfoURL: pointer.ToString("https://api.login.yahoo.com/openid/v1/userinfo"),
		Scopes:      pointer.To([]string{"openid", "profile", "email"}),
		JWKSURL:     pointer.ToString("https://api.login.yahoo.com/openid/v1/certs"),
	},
}

// NewWithOptions creates a new Yahoo OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, yahooDefaults)
}

// GetUserInfoEndpoint returns Yahoo's userinfo endpoint
func GetUserInfoEndpoint() string {
	if yahooDefaults.OIDC.UserInfoURL != nil {
		return *yahooDefaults.OIDC.UserInfoURL
	}
	return ""
}
