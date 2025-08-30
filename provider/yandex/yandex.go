package oauthgoyandex

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Yandex OAuth2/OIDC Provider Configuration
//
// Notes:
// - Yandex supports OAuth2 Authorization Code flow with refresh tokens.
// - Profile info is fetched from login.yandex.ru/info.
// - Scopes determine access (email, info, avatar, disk, etc.).
var yandexDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("yandex"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Yandex OAuth2 (no OIDC discovery doc)

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://oauth.yandex.com/authorize"),
		TokenURL:      pointer.ToString("https://oauth.yandex.com/token"),
		RevocationURL: pointer.ToString("https://oauth.yandex.com/revoke_token"),
		Scopes: pointer.To([]string{
			"login:email",
			"login:info",
		}),
		UsePKCE: pointer.ToBool(true),
	},
	UserInfoURL: pointer.ToString("https://login.yandex.ru/info"),
}

// NewWithOptions creates a new Yandex OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, yandexDefaults)
}

// GetUserInfoEndpoint returns Yandex's user info endpoint
func GetUserInfoEndpoint() string {
	if yandexDefaults.UserInfoURL != nil {
		return *yandexDefaults.UserInfoURL
	}
	return ""
}
