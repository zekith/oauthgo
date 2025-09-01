package oauthgodocusign

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildDocusignDefaults builds the Docusign provider config for sandbox or production.
// Example domain: "account-d.docusign.com" (sandbox), "account.docusign.com" (production).
func buildDocusignDefaults(domain string) *oauthgotypes.OAuth2OIDCOptions {
	authURL := fmt.Sprintf("https://%s/oauth/auth", domain)
	tokenURL := fmt.Sprintf("https://%s/oauth/token", domain)
	userInfoURL := fmt.Sprintf("https://%s/oauth/userinfo", domain)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("docusign"),
		Mode: pointer.To(oauthgotypes.OIDC), // DocuSign supports OAuth2 + OpenID, but no discovery

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:  pointer.ToString(authURL),
			TokenURL: pointer.ToString(tokenURL),
			Scopes: pointer.To([]string{
				"signature",
				"openid",
				"profile",
				"email",
			}),
			UsePKCE: pointer.ToBool(true),
		},

		OIDC: &oauthgotypes.OIDCOptions{
			Issuer:      pointer.ToString("https://" + domain + "/"),
			UserInfoURL: pointer.ToString(userInfoURL),
			Scopes:      pointer.To([]string{"signature", "openid", "profile", "email"}),
			JWKSURL:     pointer.ToString("https://" + domain + "/openid-configuration/jwks"),
		},

		UserInfoURL: pointer.ToString(userInfoURL),
	}
}

// NewWithOptions creates a new DocuSign OAuth2 provider with defaults for the given domain.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	domain := "account.docusign.com" // default production
	if providerConfig.ExtraConfig != nil {
		result, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

		if ok {
			domain = result
		}
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildDocusignDefaults(domain))
}

// GetUserInfoEndpoint returns Docusign's user info endpoint for the given domain.
func GetUserInfoEndpoint(domain string) string {
	return fmt.Sprintf("https://%s/oauth/userinfo", domain)
}
