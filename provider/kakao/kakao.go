package oauthgokakao

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Kakao OAuth2/OIDC Provider Configuration
//
// Notes:
// - Kakao supports OAuth2 Authorization Code + PKCE.
// - User profile is retrieved via https://kapi.kakao.com/v2/user/me
// - Refresh tokens are supported.
// - Scopes must be enabled in the Kakao Developer Console.
var kakaoDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("kakao"),
	Mode: pointer.To(oauthgotypes.OIDC), // Kakao supports OAuth2 and OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://kauth.kakao.com/oauth/authorize"),
		TokenURL:      pointer.ToString("https://kauth.kakao.com/oauth/token"),
		RevocationURL: pointer.ToString("https://kapi.kakao.com/v1/user/unlink"), // logout/unlink
		Scopes: pointer.To([]string{
			"profile_nickname",
			"profile_image",
		}),
		UsePKCE: pointer.ToBool(true),
	},
	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://kauth.kakao.com"),
		UserInfoURL: pointer.ToString("https://kapi.kakao.com/v2/user/me"),
		Scopes:      pointer.To([]string{"openid", "profile"}),
		JWKSURL:     pointer.ToString("https://kauth.kakao.com/.well-known/jwks.json"),
	},
}

// NewWithOptions creates a new Kakao OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, kakaoDefaults)
}

// GetUserInfoEndpoint returns Kakao's user info endpoint
func GetUserInfoEndpoint() string {
	if kakaoDefaults.OIDC.UserInfoURL != nil {
		return *kakaoDefaults.OIDC.UserInfoURL
	}
	return ""
}
