package oauthgosalesforce

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Salesforce
var salesforceDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("salesforce"),
	Mode: pointer.To(oauthgotypes.OIDC), // Salesforce supports OIDC + OAuth2

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://login.salesforce.com/services/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://login.salesforce.com/services/oauth2/token"),
		RevocationURL: pointer.ToString("https://login.salesforce.com/services/oauth2/revoke"),
		Scopes: pointer.To([]string{
			"openid", "profile", "email", "api", "refresh_token", "offline_access",
		}),
		UsePKCE: pointer.ToBool(true),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:           pointer.ToString("https://login.salesforce.com"),
		UserInfoURL:      pointer.ToString("https://login.salesforce.com/services/oauth2/userinfo"),
		JWKSURL:          pointer.ToString("https://login.salesforce.com/id/keys"), // JWKS endpoint
		Scopes:           pointer.To([]string{"openid", "profile", "email", "offline_access"}),
		DisableDiscovery: pointer.ToBool(true), // use manual config
	},
	UserInfoURL: pointer.ToString("https://login.salesforce.com/services/oauth2/userinfo"),
}

// NewWithOptions creates a new Salesforce OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, salesforceDefaults)
}

// GetUserInfoEndpoint returns Salesforce's userinfo endpoint
func GetUserInfoEndpoint() string {
	if salesforceDefaults.UserInfoURL != nil {
		return *salesforceDefaults.UserInfoURL
	}
	return ""
}
