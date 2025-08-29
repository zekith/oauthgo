package oauthgobitbucket

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

var bitbucketDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("bitbucket"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Bitbucket supports OAuth2, not full OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://bitbucket.org/site/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://bitbucket.org/site/oauth2/access_token"),
		RevocationURL: nil, // Bitbucket does not expose an RFC7009 revocation endpoint
		Scopes: pointer.To([]string{
			"account",    // read user profile
			"repository", // access repositories
		}),
		UsePKCE: pointer.ToBool(true), // PKCE is supported
	},

	// No OIDC support in Bitbucket — set OIDC fields to nil
	OIDC: nil,
}

// NewWithOptions creates a new Bitbucket OAuth2 provider with defaults.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, bitbucketDefaults)
}

// GetUserInfoEndpoint returns the Bitbucket user endpoint (used instead of OIDC /userinfo).
func GetUserInfoEndpoint() string {
	return "https://api.bitbucket.org/2.0/user"
}
