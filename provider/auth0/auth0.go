package oauthgoauth0

import (
	"fmt"

	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

// buildAuth0Defaults dynamically builds the Auth0 provider defaults based on the given domain.
func buildAuth0Defaults(domain string) *oauthgotypes.OAuth2OIDCOptions {
	baseURL := fmt.Sprintf("https://%s", domain)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("auth0"),
		Mode: pointer.To(oauthgotypes.OIDC),

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(baseURL + "/authorize"),
			TokenURL:      pointer.ToString(baseURL + "/oauth/token"),
			RevocationURL: pointer.ToString(baseURL + "/oauth/revoke"),
			Scopes:        pointer.To([]string{"openid", "profile", "email", "offline_access"}),
			UsePKCE:       pointer.ToBool(true),
		},

		OIDC: &oauthgotypes.OIDCOptions{
			Issuer:           pointer.ToString(baseURL + "/"),
			JWKSURL:          pointer.ToString(baseURL + "/.well-known/jwks.json"),
			UserInfoURL:      pointer.ToString(baseURL + "/userinfo"),
			Scopes:           pointer.To([]string{"openid", "profile", "email", "offline_access"}),
			DisableDiscovery: pointer.ToBool(false),
		},
	}
}

// NewWithOptions creates a new Auth0 OAuth2/OIDC provider with defaults for the given domain.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	if providerConfig.ExtraConfig == nil {
		return nil, fmt.Errorf("extra config is required for auth0")
	}
	domain, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

	if !ok {
		return nil, fmt.Errorf("domain is required for auth0")
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildAuth0Defaults(domain))
}

// GetUserInfoEndpoint returns the configured Auth0 userinfo endpoint for the given domain.
func GetUserInfoEndpoint(domain string) string {
	return fmt.Sprintf("https://%s/userinfo", domain)
}
