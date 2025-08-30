package oauthgostrava

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Strava OAuth2 Provider Configuration
//
// Notes:
// - Strava uses OAuth2 with short-lived access tokens (~6 hours).
// - Refresh tokens are long-lived and must be stored for future use.
// - Scopes define access (read profile, read/write activities, etc.).
// - The /token response includes both tokens and the athlete profile.
var stravaDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("strava"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2 only (no OIDC discovery)

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:  pointer.ToString("https://www.strava.com/oauth/authorize"),
		TokenURL: pointer.ToString("https://www.strava.com/oauth/token"),
		// Strava supports explicit deauthorization (revoke)
		RevocationURL: pointer.ToString("https://www.strava.com/oauth/deauthorize"),
		Scopes: pointer.To([]string{
			"read", // Read public profile data
		}),
		UsePKCE: pointer.ToBool(true),
	},

	UserInfoURL: pointer.ToString("https://www.strava.com/api/v3/athlete"),
}

// NewWithOptions creates a new Strava OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, stravaDefaults)
}

// GetUserInfoEndpoint returns Strava's athlete profile endpoint
func GetUserInfoEndpoint() string {
	if stravaDefaults.UserInfoURL != nil {
		return *stravaDefaults.UserInfoURL
	}
	return ""
}
