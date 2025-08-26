package oauthgogoogle

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

var googleDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("google"),
	Mode: pointer.To(oauthgotypes.OIDC), // Google strongly recommends OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://accounts.google.com/o/oauth2/v2/auth"),
		TokenURL:      pointer.ToString("https://oauth2.googleapis.com/token"),
		RevocationURL: pointer.ToString("https://oauth2.googleapis.com/revoke"),
		Scopes:        pointer.To([]string{"email"}), // Applicable for OAuth2-only mode will be overridden by OIDC scopes if OIDC is enabled
		ExtraAuth: pointer.To(map[string]string{
			"access_type": "offline",
		}),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer: pointer.ToString("https://accounts.google.com"),
		Scopes: pointer.To([]string{"openid", "profile", "email"}), // Applicable for OIDC mode
	},
}

func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, googleDefaults)
}
