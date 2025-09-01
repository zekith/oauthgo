package oauthgoconcur

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

const defaultDomain = "us.api.concursolutions.com" // default to Sandbox

// buildConcurDefaults builds the Concur provider config for sandbox or production.
// domain should be "us.api.concursolutions.com" for Sandbox or "www.concursolutions.com" for Production.
func buildConcurDefaults(domain string) *oauthgotypes.OAuth2OIDCOptions {
	if domain == "" {
		domain = defaultDomain
	}

	authURL := "https://" + domain + "/oauth2/v0/authorize"
	tokenURL := "https://" + domain + "/oauth2/v0/token"
	userInfoURL := "https://" + domain + "/profile/v1/me"

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("concur"),
		Mode: pointer.To(oauthgotypes.OAuth2Only), // Concur supports OAuth2, not OIDC

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:  pointer.ToString(authURL),
			TokenURL: pointer.ToString(tokenURL),
			Scopes: pointer.To([]string{
				"user.read",
				"offline_access", // ensure refresh tokens
			}),
			UsePKCE: pointer.ToBool(true),
		},

		UserInfoURL: pointer.ToString(userInfoURL),
	}
}

// NewWithOptions creates a new SAP Concur OAuth2 provider with defaults for the given domain.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	domain := defaultDomain
	if providerConfig.ExtraConfig != nil {
		result, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

		if ok {
			domain = result
		}
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildConcurDefaults(domain))
}

// GetUserInfoEndpoint returns SAP Concur's profile endpoint for the given domain.
func GetUserInfoEndpoint(domain string) string {
	if domain == "" {
		domain = defaultDomain
	}
	return "https://" + domain + "/profile/v1/me"
}
