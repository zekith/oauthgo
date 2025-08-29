package oauthgoreddit

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Reddit
var redditDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("reddit"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Reddit supports OAuth2, not full OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://www.reddit.com/api/v1/authorize"),
		TokenURL:      pointer.ToString("https://www.reddit.com/api/v1/access_token"),
		RevocationURL: pointer.ToString("https://www.reddit.com/api/v1/revoke_token"), // not always used; can revoke via access_token
		Scopes: pointer.To([]string{
			"identity", "read", "submit", "vote", // common scopes
		}),
		UsePKCE: pointer.ToBool(true), // PKCE is supported
		ExtraAuth: pointer.To(map[string]string{
			"duration": "permanent", // request refresh tokens
		}),
	},
	UserInfoURL: pointer.ToString("https://oauth.reddit.com/api/v1/me"),
}

// NewWithOptions creates a new Reddit OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, redditDefaults)
}

// GetUserInfoEndpoint returns Reddit's "me" endpoint
func GetUserInfoEndpoint() string {
	if redditDefaults.UserInfoURL != nil {
		return *redditDefaults.UserInfoURL
	}
	return ""
}
