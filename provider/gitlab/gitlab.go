package oauthgogitlab

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

var gitlabDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("gitlab"),
	Mode: pointer.To(oauthgotypes.OIDC), // GitLab supports OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://gitlab.com/oauth/authorize"),
		TokenURL:      pointer.ToString("https://gitlab.com/oauth/token"),
		RevocationURL: pointer.ToString("https://gitlab.com/oauth/revoke"), // GitLab supports RFC7009
		Scopes: pointer.To([]string{
			"openid", "profile", "email", // OIDC scopes
			"read_user", // GitLab API scope to fetch user profile
		}),
		ExtraAuth: pointer.To(map[string]string{
			"access_type":           "offline", // request refresh tokens
			"code_challenge_method": "S256",    // GitLab recommends PKCE for public clients
		}),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://gitlab.com"),
		Scopes:      pointer.To([]string{"openid", "profile", "email"}),
		JWKSURL:     pointer.ToString("https://gitlab.com/oauth/discovery/keys"),
		UserInfoURL: pointer.ToString("https://gitlab.com/oauth/userinfo"),
	},
}

// NewWithOptions creates a new GitLab OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, gitlabDefaults)
}

func GetUserInfoEndpoint() string {
	if gitlabDefaults.OIDC != nil && gitlabDefaults.OIDC.UserInfoURL != nil {
		return *gitlabDefaults.OIDC.UserInfoURL
	}
	return ""
}
