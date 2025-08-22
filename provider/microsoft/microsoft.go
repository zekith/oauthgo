package oauthgomicrosoft

import (
	"github.com/AlekSi/pointer"
	oauthgohelper "github.com/zekith/oauthgo/core/helper"
	coreprov "github.com/zekith/oauthgo/core/provider"
)

var microsoftDefaults = &coreprov.ProviderOptions{
	Name: pointer.ToString("microsoft"),
	Mode: pointer.To(coreprov.OIDC), // Microsoft supports OIDC (recommended)

	OAuth2: &coreprov.OAuth2Options{
		AuthURL:       pointer.ToString("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
		TokenURL:      pointer.ToString("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
		RevocationURL: pointer.ToString("https://login.microsoftonline.com/common/oauth2/v2.0/logout"),
		Scopes:        pointer.To([]string{"openid", "profile", "email", "offline_access"}),
	},
	OIDC: &coreprov.OIDCOptions{
		Issuer:                     pointer.ToString("https://login.microsoftonline.com/common/v2.0"),
		UserInfoURL:                pointer.ToString("https://graph.microsoft.com/oidc/userinfo"),
		JWKSURL:                    pointer.ToString("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
		DisableDiscovery:           pointer.ToBool(true),
		Scopes:                     pointer.To([]string{"openid", "profile", "email", "offline_access"}),
		DisableIdTokenVerification: pointer.ToBool(true),
	},
}

func NewWithOptions(input *coreprov.ProviderInput) (coreprov.Provider, error) {
	return oauthgohelper.BuildProviderFromDefaults(input, microsoftDefaults)
}
