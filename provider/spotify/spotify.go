package oauthgospotify

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

var spotifyDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("spotify"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2 only

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://accounts.spotify.com/authorize"),
		TokenURL:      pointer.ToString("https://accounts.spotify.com/api/token"),
		RevocationURL: nil, // Spotify does not provide RFC7009 revocation endpoint
		Scopes: pointer.To([]string{
			"user-read-email",
			"user-read-private",
		}),
		UsePKCE: pointer.ToBool(true), // PKCE is supported & recommended
	},
	UserInfoURL: pointer.ToString("https://api.spotify.com/v1/me"),
}

// NewWithOptions creates a new Spotify OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, spotifyDefaults)
}

// GetUserInfoEndpoint returns Spotify's /me endpoint
func GetUserInfoEndpoint() string {
	if spotifyDefaults.UserInfoURL != nil {
		return *spotifyDefaults.UserInfoURL
	}
	return ""
}
