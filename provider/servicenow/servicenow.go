package oauthgoservicenow

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildServiceNowDefaults builds the ServiceNow provider config for a given instance domain.
// Example domain: "dev12345.service-now.com" or "yourcompany.service-now.com"
func buildServiceNowDefaults(domain string) *oauthgotypes.OAuth2OIDCOptions {
	authURL := fmt.Sprintf("https://%s/oauth_auth.do", domain)
	tokenURL := fmt.Sprintf("https://%s/oauth_token.do", domain)
	revocationURL := fmt.Sprintf("https://%s/oauth_revoke.do", domain)
	userInfoURL := fmt.Sprintf("https://%s/api/now/table/sys_user?sysparm_query=user_name=javascript:gs.getUserName()", domain)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("servicenow"),
		Mode: pointer.To(oauthgotypes.OAuth2Only), // ServiceNow supports OAuth2 (no OIDC discovery)

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(authURL),
			TokenURL:      pointer.ToString(tokenURL),
			RevocationURL: pointer.ToString(revocationURL),
			Scopes: pointer.To([]string{
				"useraccount",
				"openid",
			}),
			UsePKCE: pointer.ToBool(true),
		},
		UserInfoURL: pointer.ToString(userInfoURL),
	}
}

// NewWithOptions creates a new ServiceNow OAuth2 provider with defaults for the given instance.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	domain := ""
	if providerConfig.ExtraConfig != nil {
		result, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

		if ok {
			domain = result
		}
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildServiceNowDefaults(domain))
}

// GetUserInfoEndpoint returns ServiceNow's sys_user endpoint for the given instance.
func GetUserInfoEndpoint(domain string) string {
	return fmt.Sprintf("https://%s/api/now/table/sys_user?sysparm_query=user_name=javascript:gs.getUserName()", domain)
}
