package oauthgogitea

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Gitea
// NOTE: Replace "https://gitea.com" with your Gitea base URL (include subpath if any, e.g., https://git.com/gitea).
var giteaDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("gitea"),
	Mode: pointer.To(oauthgotypes.OIDC), // Gitea supports OAuth2 + OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://gitea.com/login/oauth/authorize"),
		TokenURL:      pointer.ToString("https://gitea.com/login/oauth/access_token"),
		RevocationURL: nil, // Gitea doesn't expose an RFC7009 revocation endpoint
		Scopes:        pointer.To([]string{"openid", "profile", "email"}),
		UsePKCE:       pointer.ToBool(true),
	},
	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://gitea.com"),
		UserInfoURL: pointer.ToString("https://gitea.com/login/oauth/userinfo"),
		JWKSURL:     pointer.ToString("https://gitea.com/login/oauth/keys"),
		Scopes:      pointer.To([]string{"openid", "profile", "email"}),
	},
}

// NewWithOptions creates a new Gitea OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, giteaDefaults)
}

// GetUserInfoEndpoint returns Gitea's OIDC userinfo endpoint
func GetUserInfoEndpoint() string {
	if giteaDefaults.OIDC.UserInfoURL != nil {
		return *giteaDefaults.OIDC.UserInfoURL
	}
	return ""
}
