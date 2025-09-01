package oauthgozendesk

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildZendeskDefaults builds the Zendesk provider config for a given domain.
// Example domain: "zekith.zendesk.com"
func buildZendeskDefaults(domain string) *oauthgotypes.OAuth2OIDCOptions {
	authURL := fmt.Sprintf("https://%s/oauth/authorizations/new", domain)
	tokenURL := fmt.Sprintf("https://%s/oauth/tokens", domain)
	userInfoURL := fmt.Sprintf("https://%s/api/v2/users/me.json", domain)
	revokeURL := fmt.Sprintf("https://%s/api/v2/oauth/tokens/current.json", domain)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("zendesk"),
		Mode: pointer.To(oauthgotypes.OAuth2Only), // Zendesk supports OAuth2 only, no OIDC discovery

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(authURL),
			TokenURL:      pointer.ToString(tokenURL),
			RevocationURL: pointer.ToString(revokeURL),
			Scopes: pointer.To([]string{
				"read",
				"write",
			}),
			UsePKCE: pointer.ToBool(true),
		},

		UserInfoURL: pointer.ToString(userInfoURL),
	}
}

// NewWithOptions creates a new Zendesk OAuth2 provider with defaults for the given subdomain.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	domain := ""
	if providerConfig.ExtraConfig != nil {
		result, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

		if ok {
			domain = result
		}
	}

	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildZendeskDefaults(domain))
}

// GetUserInfoEndpoint returns Zendesk's "users/me" endpoint for the given subdomain.
func GetUserInfoEndpoint(domain string) string {
	return fmt.Sprintf("https://%s/api/v2/users/me.json", domain)
}
