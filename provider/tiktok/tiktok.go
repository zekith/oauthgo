package oauthgotiktok

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// TikTok OAuth2 Provider Configuration
//
// Notes:
// - TikTok uses `client_key` instead of `client_id` terminology.
// - Authorization Code Flow with PKCE is supported.
// - User profile data is retrieved using the /user/info/ endpoint with open_id.
var tiktokDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("tiktok"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // TikTok supports OAuth2, not full OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://www.tiktok.com/v2/auth/authorize/"),
		TokenURL:      pointer.ToString("https://open-api.tiktokglobalplatform.com/v2/oauth/token/"),
		RevocationURL: pointer.ToString("https://open-api.tiktokglobalplatform.com/v2/oauth/revoke/"), // optional
		Scopes: pointer.To([]string{
			"user.info.basic",
			"user.info.profile",
			"user.info.stats",
			"video.list",
			"video.upload",
		}),
		UsePKCE: pointer.ToBool(true),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:                     pointer.ToString("https://www.tiktok.com"),
		UserInfoURL:                pointer.ToString("https://open-api.tiktokglobalplatform.com/v2/user/info/"),
		Scopes:                     pointer.To([]string{"user.info.basic", "user.info.profile", "user.info.stats"}),
		DisableIdTokenVerification: pointer.ToBool(true),
	},
}

// NewWithOptions creates a new TikTok OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, tiktokDefaults)
}

// GetUserInfoEndpoint returns TikTok's user info endpoint
func GetUserInfoEndpoint() string {
	if tiktokDefaults.OIDC.UserInfoURL != nil {
		return *tiktokDefaults.OIDC.UserInfoURL
	}
	return ""
}
