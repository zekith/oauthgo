package oauthgoinstagram

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Instagram Basic Display API uses OAuth 2.0 (NOT OIDC).
// No standard RFC7009 revocation endpoint; tokens are short-lived and can be
// exchanged for long-lived tokens via Graph API (server-side).
// Scopes commonly: "user_profile", "user_media".
//
// Long-lived exchange (server flow, not part of this config):
//
//	GET https://graph.instagram.com/access_token
//	    ?grant_type=ig_exchange_token
//	    &client_secret=APP_SECRET
//	    &access_token=SHORT_LIVED_TOKEN
//
// Refresh long-lived token (server flow):
//
//	GET https://graph.instagram.com/refresh_access_token
//	    ?grant_type=ig_refresh_token
//	    &access_token=LONG_LIVED_TOKEN
var instagramDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("instagram"),
	Mode: pointer.To(oauthgotypes.OAuth2Only),

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:  pointer.ToString("https://api.instagram.com/oauth/authorize"),
		TokenURL: pointer.ToString("https://api.instagram.com/oauth/access_token"),
		// RevocationURL: (none for Instagram Basic Display)
		Scopes: pointer.To([]string{"user_profile", "user_media"}),

		// Instagram Basic Display does not support PKCE; disable to avoid adding code_challenge.
		UsePKCE:          pointer.To(false),
		PKCEPublicClient: pointer.To(false),
	},

	// OIDC isn't supported for Instagram Basic Display; keep nil.
	OIDC: nil,
}

func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, instagramDefaults)
}
