package oauthgoline

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// LINE OAuth2 Provider Configuration
//
// Notes:
// - LINE Login supports OAuth2 and OpenID Connect.
// - Refresh tokens are issued if requested.
// - Profile and email data can be retrieved via /v2/profile and ID token claims.
var lineDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("line"),
	Mode: pointer.To(oauthgotypes.OIDC), // LINE supports OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:  pointer.ToString("https://access.line.me/oauth2/v2.1/authorize"),
		TokenURL: pointer.ToString("https://api.line.me/oauth2/v2.1/token"),
		// LINE also supports revocation
		RevocationURL: pointer.ToString("https://api.line.me/oauth2/v2.1/revoke"),
		Scopes: pointer.To([]string{
			"openid",
			"profile",
			"email",
		}),
		UsePKCE: pointer.ToBool(true),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:                     pointer.ToString("https://access.line.me"),
		UserInfoURL:                pointer.ToString("https://api.line.me/v2/profile"),
		Scopes:                     pointer.To([]string{"openid", "profile", "email"}),
		DisableIdTokenVerification: pointer.ToBool(true),
	},
}

// NewWithOptions creates a new LINE OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, lineDefaults)
}

// GetUserInfoEndpoint returns LINE's profile endpoint
func GetUserInfoEndpoint() string {
	if lineDefaults.OIDC.UserInfoURL != nil {
		return *lineDefaults.OIDC.UserInfoURL
	}
	return ""
}
