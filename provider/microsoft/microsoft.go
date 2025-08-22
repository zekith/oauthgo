package oauthgomicrosoft

import (
	"github.com/AlekSi/pointer"
	coreprov "github.com/zekith/oauthgo/core/provider"
	"github.com/zekith/oauthgo/core/provider/helper"
	"github.com/zekith/oauthgo/core/types"
)

var microsoftDefaults = &oauthgotypes.ProviderOptions{
	Name: pointer.ToString("microsoft"),
	Mode: pointer.To(oauthgotypes.OIDC), // Microsoft supports OIDC (recommended)

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
		TokenURL:      pointer.ToString("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
		RevocationURL: pointer.ToString("https://login.microsoftonline.com/common/oauth2/v2.0/logout"),
		Scopes:        pointer.To([]string{"openid", "profile", "email", "offline_access"}),
	},
	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:                     pointer.ToString("https://login.microsoftonline.com/common/v2.0"),
		UserInfoURL:                pointer.ToString("https://graph.microsoft.com/oidc/userinfo"),
		JWKSURL:                    pointer.ToString("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
		DisableDiscovery:           pointer.ToBool(true),
		Scopes:                     pointer.To([]string{"openid", "profile", "email", "offline_access"}),
		DisableIdTokenVerification: pointer.ToBool(true),
	},
}

func NewWithOptions(input *oauthgotypes.ProviderInput) (coreprov.Provider, error) {
	return oauthgohelper.BuildProviderFromDefaults(input, microsoftDefaults)
}
