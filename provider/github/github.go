package oauthgogithub

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

var githubDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("github"),
	Mode: pointer.To(oauthgotypes.OAuth2Only),

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://github.com/login/oauth/authorize"),
		TokenURL:      pointer.ToString("https://github.com/login/oauth/access_token"),
		RevocationURL: nil, // GitHub does not support revocation
		Scopes:        pointer.To([]string{"read:user", "user:email"}),
	},
	OIDC:        nil, // GitHub does not support OIDC
	UserInfoURL: pointer.ToString("https://api.github.com/user"),
}

func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, githubDefaults)
}

func GetUserInfoEndpoint() string {
	if githubDefaults.UserInfoURL != nil {
		return *githubDefaults.UserInfoURL
	}
	return ""
}
