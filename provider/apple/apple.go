package oauthgoapple

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Apple OAuth2/OIDC Provider Configuration
//
// Notes:
// - Apple requires JWT-based client_secret (signed with your .p8 key).
// - User profile info (name, email) is returned inside the ID Token (JWT) and callback POST body.
// - No /userinfo endpoint exists; you must decode ID Token instead.
var appleDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("apple"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Apple supports OIDC, but there is a custom implementation, hence OAuth2Only

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://appleid.apple.com/auth/authorize"),
		TokenURL:      pointer.ToString("https://appleid.apple.com/auth/token"),
		RevocationURL: pointer.ToString("https://appleid.apple.com/auth/revoke"),
		Scopes: pointer.To([]string{
			"openid",
			"name",
			"email",
		}),
		UsePKCE: pointer.ToBool(true), // PKCE is supported
	},
	UserInfoURL: nil, // user info must be extracted from ID Token
}

// NewWithOptions creates a new Apple OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, appleDefaults)
}

// GetUserInfoEndpoint is unsupported for Apple since user info is only in the ID Token.
// Instead, decode the ID Token (JWT) to extract user claims.
func GetUserInfoEndpoint() string {
	return "" // not applicable
}
