package oauthgoslack

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

var slackDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("slack"),
	// Slack supports OpenID Connect for "Sign in with Slack"
	Mode: pointer.To(oauthgotypes.OIDC),

	// OAuth 2.0 endpoints (used if Mode == OAuth2Only)
	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://slack.com/openid/connect/authorize"),
		TokenURL:      pointer.ToString("https://slack.com/api/openid.connect.token"),
		RevocationURL: pointer.ToString("https://slack.com/api/auth.revoke"),
		// Typical placeholder scope for classic OAuth; override per app needs.
		Scopes:           pointer.To([]string{"users:read"}),
		PKCEPublicClient: pointer.ToBool(false), // Slack does not support PKCE for OAuth2
		// If you want to force extra params in the authorize URL, add them here:
		// ExtraAuth: pointer.To(map[string]string{"prompt": "consent"}),
		ExtraAuth: pointer.To(map[string]string{
			"grant_type": "refresh_token",
		}),
	},

	// OIDC (Sign in with Slack) — discovery works from the issuer
	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://slack.com"),
		Scopes:      pointer.To([]string{"openid", "profile", "email"}),
		JWKSURL:     pointer.ToString("https://slack.com/openid/connect/keys"),
		UserInfoURL: pointer.ToString("https://slack.com/api/openid.connect.userInfo"),
	},
}

func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, slackDefaults)
}

func GetUserInfoEndpoint() string {
	if slackDefaults.OIDC != nil && slackDefaults.OIDC.UserInfoURL != nil {
		return *slackDefaults.OIDC.UserInfoURL
	}
	return ""
}
