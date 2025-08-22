package oauthgogoogle

import (
	"github.com/AlekSi/pointer"
	oauthgohelper "github.com/zekith/oauthgo/core/helper"
	coreprov "github.com/zekith/oauthgo/core/provider"
)

var googleDefaults = &coreprov.ProviderOptions{
	Name: pointer.ToString("google"),
	Mode: pointer.To(coreprov.OIDC), // Google strongly recommends OIDC

	OAuth2: &coreprov.OAuth2Options{
		AuthURL:       pointer.ToString("https://accounts.google.com/o/oauth2/v2/auth"),
		TokenURL:      pointer.ToString("https://oauth2.googleapis.com/token"),
		RevocationURL: pointer.ToString("https://oauth2.googleapis.com/revoke"),
		Scopes:        pointer.To([]string{"email"}), // Applicable for OAuth2-only mode will be overridden by OIDC scopes if OIDC is enabled
	},

	OIDC: &coreprov.OIDCOptions{
		Issuer: pointer.ToString("https://accounts.google.com"),
		Scopes: pointer.To([]string{"openid", "profile", "email"}), // Applicable for OIDC mode
	},
}

func NewWithOptions(input *coreprov.ProviderInput) (coreprov.Provider, error) {
	return oauthgohelper.BuildProviderFromDefaults(input, googleDefaults)
}
