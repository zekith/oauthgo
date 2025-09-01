package oauthgoboldsign

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// boldsignDefaults contains the static BoldSign OAuth2/OIDC configuration.
var boldsignDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("boldsign"),
	Mode: pointer.To(oauthgotypes.OIDC), // BoldSign supports OIDC (preferred)

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://account.boldsign.com/connect/authorize"),
		TokenURL:      pointer.ToString("https://account.boldsign.com/connect/token"),
		RevocationURL: pointer.ToString("https://account.boldsign.com/connect/revocation"),
		Scopes: pointer.To([]string{
			"openid",
			"profile",
			"email",
			"offline_access",         // request refresh tokens
			"BoldSign.Documents.All", // full documents API access
			"BoldSign.Users.Read",    // read user info
		}),
		UsePKCE: pointer.ToBool(true),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://account.boldsign.com"),
		UserInfoURL: pointer.ToString("https://account.boldsign.com/connect/userinfo"),
		Scopes: pointer.To([]string{
			"openid",
			"profile",
			"email",
			"offline_access",         // request refresh tokens
			"BoldSign.Documents.All", // full documents API access
			"BoldSign.Users.Read",    // read user info
		}),
		JWKSURL: pointer.ToString("https://account.boldsign.com/.well-known/openid-configuration/jwks"),
	},

	UserInfoURL: pointer.ToString("https://account.boldsign.com/connect/userinfo"),
}

// NewWithOptions creates a new BoldSign OAuth2/OIDC provider with defaults.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, boldsignDefaults)
}

// GetUserInfoEndpoint returns BoldSign's OIDC UserInfo endpoint.
func GetUserInfoEndpoint() string {
	return "https://account.boldsign.com/connect/userinfo"
}
