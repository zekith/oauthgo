package oauthgomicrosoft

import (
	"fmt"

	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

// buildMicrosoftDefaults builds the Microsoft provider config for a given tenant identifier.
// tenant can be "common", "organizations", "consumers", or a specific tenant ID/domain.
func buildMicrosoftDefaults(tenant string) *oauthgotypes.OAuth2OIDCOptions {
	if tenant == "" {
		tenant = "common" // default to common
	}
	baseAuthURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0", tenant)
	baseIssuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)
	baseJWKS := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenant)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("microsoft"),
		Mode: pointer.To(oauthgotypes.OIDC), // Microsoft supports OIDC

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(baseAuthURL + "/authorize"),
			TokenURL:      pointer.ToString(baseAuthURL + "/token"),
			RevocationURL: pointer.ToString(baseAuthURL + "/logout"),
			Scopes:        pointer.To([]string{"openid", "profile", "email", "offline_access"}),
		},
		OIDC: &oauthgotypes.OIDCOptions{
			Issuer:                     pointer.ToString(baseIssuer),
			UserInfoURL:                pointer.ToString("https://graph.microsoft.com/oidc/userinfo"),
			JWKSURL:                    pointer.ToString(baseJWKS),
			DisableDiscovery:           pointer.ToBool(true), // manual config
			Scopes:                     pointer.To([]string{"openid", "profile", "email", "offline_access"}),
			DisableIdTokenVerification: pointer.ToBool(true), // useful in multi-tenant/common flows
		},
	}
}

// NewWithOptions creates a new Microsoft OAuth2/OIDC provider for the given tenant.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	domain := ""
	if providerConfig.ExtraConfig != nil {
		result, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

		if ok {
			domain = result
		}
	}

	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildMicrosoftDefaults(domain))
}

// GetUserInfoEndpoint returns the Microsoft Graph UserInfo endpoint.
func GetUserInfoEndpoint() string {
	return "https://graph.microsoft.com/oidc/userinfo"
}
