package oauthgoworkday

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildWorkdayDefaults builds the Workday provider config for a given tenant.
// Example tenant: "yourtenant" -> https://yourtenant.workday.com/ccx/oauth2/yourtenant
func buildWorkdayDefaults(tenant string) *oauthgotypes.OAuth2OIDCOptions {

	baseURL := fmt.Sprintf("https://%s.workday.com/ccx/oauth2/%s", tenant, tenant)
	authURL := fmt.Sprintf("%s/authorize", baseURL)
	tokenURL := fmt.Sprintf("%s/token", baseURL)
	userInfoURL := fmt.Sprintf("https://%s.workday.com/ccx/api/v1/%s/workers/me", tenant, tenant) // example for user context

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("workday"),
		Mode: pointer.To(oauthgotypes.OAuth2Only), // Workday supports OAuth2, not OIDC discovery

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:  pointer.ToString(authURL),
			TokenURL: pointer.ToString(tokenURL),
			Scopes: pointer.To([]string{
				"openid",
				"profile",
				"email",
				"offline_access",
			}),
			UsePKCE: pointer.ToBool(true),
		},

		OIDC: &oauthgotypes.OIDCOptions{
			Issuer:           pointer.ToString(baseURL),
			UserInfoURL:      pointer.ToString(userInfoURL),
			Scopes:           pointer.To([]string{"openid", "profile", "email"}),
			DisableDiscovery: pointer.ToBool(true),
		},

		UserInfoURL: pointer.ToString(userInfoURL),
	}
}

// NewWithOptions creates a new Workday OAuth2 provider with defaults for the given tenant.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	tenant := ""
	if providerConfig.ExtraConfig != nil {
		result, ok := pointer.Get(providerConfig.ExtraConfig)["tenant"]

		if ok {
			tenant = result
		}
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildWorkdayDefaults(tenant))
}

// GetUserInfoEndpoint returns Workday's worker info endpoint for the given tenant.
func GetUserInfoEndpoint(tenant string) string {
	return fmt.Sprintf("https://%s.workday.com/ccx/api/v1/%s/workers/me", tenant, tenant)
}
