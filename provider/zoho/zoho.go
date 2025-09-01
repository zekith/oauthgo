package oauthgozoho

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildZohoDefaults dynamically builds the Zoho provider defaults for a given region domain.
// Examples of domain: "accounts.zoho.com", "accounts.zoho.in", "accounts.zoho.eu", "accounts.zoho.com.cn", "accounts.zoho.com.au"
func buildZohoDefaults(domain string) *oauthgotypes.OAuth2OIDCOptions {
	baseAuth := fmt.Sprintf("https://%s/oauth/v2/auth", domain)
	baseToken := fmt.Sprintf("https://%s/oauth/v2/token", domain)
	// Note: Zoho doesn't provide a universal revoke endpoint, but tokens can be invalidated via API calls

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("zoho"),
		Mode: pointer.To(oauthgotypes.OAuth2Only), // Zoho is OAuth2, no full OIDC discovery

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:  pointer.ToString(baseAuth),
			TokenURL: pointer.ToString(baseToken),
			Scopes: pointer.To([]string{
				"AaaServer.profile.Read", // basic user profile
			}),
			UsePKCE: pointer.ToBool(true),
			ExtraAuth: pointer.To(map[string]string{
				"access_type": "offline", // ensures refresh token
				"prompt":      "consent", // request fresh consent if needed
			}),
		},

		// Note: UserInfo depends on which Zoho product you integrate with (CRM, Mail, Desk, Books, etc.)
		UserInfoURL: pointer.ToString(""),
	}
}

// NewWithOptions creates a new Zoho OAuth2 provider with defaults for the given domain.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	domain := "accounts.zoho.us" // default US

	if providerConfig.ExtraConfig != nil {
		result, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

		if ok {
			domain = result
		}
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildZohoDefaults(domain))
}

// GetUserInfoEndpoint returns Zoho's UserInfo endpoint if configured.
// (Note: For Zoho, user info must be retrieved via specific product APIs, e.g., CRM, Mail)
func GetUserInfoEndpoint() string {
	// Example: CRM users endpoint (requires CRM scope)
	return "https://www.zohoapis.com/crm/v2/users"
}
