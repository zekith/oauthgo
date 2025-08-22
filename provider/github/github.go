package oauthgogithub

import (
	"github.com/AlekSi/pointer"
	oauthgohelper "github.com/zekith/oauthgo/core/helper"
	coreprov "github.com/zekith/oauthgo/core/provider"
)

var githubDefaults = &coreprov.ProviderOptions{
	Name: pointer.ToString("github"),
	Mode: pointer.To(coreprov.OAuth2Only),

	OAuth2: &coreprov.OAuth2Options{
		AuthURL:       pointer.ToString("https://github.com/login/oauth/authorize"),
		TokenURL:      pointer.ToString("https://github.com/login/oauth/access_token"),
		RevocationURL: nil, // GitHub does not support revocation
		Scopes:        pointer.To([]string{"read:user", "user:email"}),
	},
	OIDC: nil, // GitHub does not support OIDC

}

func NewWithOptions(input *coreprov.ProviderInput) (coreprov.Provider, error) {
	return oauthgohelper.BuildProviderFromDefaults(input, githubDefaults)
}
