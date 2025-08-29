package oauthgookta

import (
	"fmt"

	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

// buildOktaDefaults dynamically builds the Okta provider defaults based on the given domain.
// Example domain: "dev-123456.okta.com" or "login.mycompany.com"
func buildOktaDefaults(domain string, authServer string) *oauthgotypes.OAuth2OIDCOptions {
	if authServer == "" {
		authServer = "default"
	}
	baseURL := fmt.Sprintf("https://%s/oauth2/%s/v1", domain, authServer)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("okta"),
		Mode: pointer.To(oauthgotypes.OIDC),

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(baseURL + "/authorize"),
			TokenURL:      pointer.ToString(baseURL + "/token"),
			RevocationURL: pointer.ToString(baseURL + "/revoke"),
			Scopes:        pointer.To([]string{"openid", "profile", "email", "offline_access"}),
			UsePKCE:       pointer.ToBool(true),
		},

		OIDC: &oauthgotypes.OIDCOptions{
			Issuer:           pointer.ToString(fmt.Sprintf("https://%s/oauth2/%s", domain, authServer)),
			JWKSURL:          pointer.ToString(fmt.Sprintf("https://%s/oauth2/%s/v1/keys", domain, authServer)),
			UserInfoURL:      pointer.ToString(baseURL + "/userinfo"),
			Scopes:           pointer.To([]string{"openid", "profile", "email", "offline_access"}),
			DisableDiscovery: pointer.ToBool(false), // Okta supports discovery, but explicit is safe
		},
	}
}

// NewWithOptions creates a new Okta OAuth2/OIDC provider with defaults for the given domain.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	if providerConfig.ExtraConfig == nil {
		return nil, fmt.Errorf("extra config is required for Okta")
	}
	domain, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

	if !ok {
		return nil, fmt.Errorf("domain is required for Okta")
	}

	authServer, ok := pointer.Get(providerConfig.ExtraConfig)["authServer"]

	if !ok {
		authServer = ""
	}

	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildOktaDefaults(domain, authServer))
}

// GetUserInfoEndpoint returns the configured Okta userinfo endpoint for the given domain.
func GetUserInfoEndpoint(domain string, authServer string) string {
	if authServer == "" {
		authServer = "default"
	}
	return fmt.Sprintf("https://%s/oauth2/%s/v1/userinfo", domain, authServer)
}
