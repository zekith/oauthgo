package oauthgox

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

var xDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("x"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // X currently supports OAuth2 but not full OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://twitter.com/i/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://api.twitter.com/2/oauth2/token"),
		RevocationURL: pointer.ToString("https://api.twitter.com/2/oauth2/revoke"),
		Scopes: pointer.To([]string{
			"tweet.read",
			"tweet.write",
			"users.read",
			"offline.access", // required for refresh tokens
		}),
		ExtraAuth: pointer.To(map[string]string{
			"response_type":         "code",
			"code_challenge_method": "S256", // PKCE required
		}),
	},

	OIDC:        nil, // not applicable since X doesn't provide OpenID Connect
	UserInfoURL: pointer.ToString("https://api.x.com/2/users/me"),
}

// NewWithOptions creates a new X OAuth2 provider with the given config
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, xDefaults)
}

func GetUserInfoEndpoint() string {

	if xDefaults.UserInfoURL != nil {
		return *xDefaults.UserInfoURL
	}
	return ""
}
