package oauthgofacebook

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

var facebookDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("facebook"),
	// Facebook Login supports OIDC Authorization Code (+ PKCE). If you want classic OAuth only, set OAuth2Only.
	Mode: pointer.To(oauthgotypes.OIDC),

	OAuth2: &oauthgotypes.OAuth2Options{
		// Version the endpoints to your target Graph API version.
		AuthURL:  pointer.ToString("https://www.facebook.com/v20.0/dialog/oauth"),
		TokenURL: pointer.ToString("https://graph.facebook.com/v20.0/oauth/access_token"),
		// Facebook doesn't provide a standard RFC7009 revocation endpoint; omit RevocationURL.
		Scopes: pointer.To([]string{"public_profile", "email"}),
		ExtraAuth: pointer.To(map[string]string{
			// Ask again for declined permissions when needed.
			"auth_type": "rerequest",
		}),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		// Facebook’s OIDC issuer
		Issuer: pointer.ToString("https://www.facebook.com"),
		// Standard OIDC scopes supported by Facebook Login
		Scopes:      pointer.To([]string{"openid", "email", "public_profile"}),
		JWKSURL:     pointer.ToString("https://www.facebook.com/.well-known/oauth/openid/jwks/"),
		UserInfoURL: pointer.ToString("https://graph.facebook.com/me?fields=id,name,email"),
	},
}

func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, facebookDefaults)
}

func GetUserInfoEndpoint() string {

	if facebookDefaults.OIDC != nil && facebookDefaults.OIDC.UserInfoURL != nil {
		return *facebookDefaults.OIDC.UserInfoURL
	}
	return ""
}
