package oauthgogithub

import (
	"github.com/AlekSi/pointer"
	coreprov "github.com/zekith/oauthgo/core/provider"
	"github.com/zekith/oauthgo/core/provider/factory"
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
	OIDC: nil, // GitHub does not support OIDC

}

func NewWithOptions(input *oauthgotypes.ProviderInput) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuthOIDCProvider(input, githubDefaults)
}
