package oauthgouber

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildUberDefaults builds the Uber OAuth2 config based on environment domain.
// Use "login.uber.com" for production and "sandbox-login.uber.com" for sandbox.
func buildUberDefaults(domain string) *oauthgotypes.OAuth2OIDCOptions {
	if domain == "" {
		domain = "login.uber.com" // default to production
	}
	baseAuth := fmt.Sprintf("https://%s/oauth/v2", domain)
	apiBase := "https://api.uber.com"
	if domain == "sandbox-login.uber.com" {
		apiBase = "https://sandbox-api.uber.com"
	}

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("uber"),
		Mode: pointer.To(oauthgotypes.OAuth2Only),

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(baseAuth + "/authorize"),
			TokenURL:      pointer.ToString(baseAuth + "/token"),
			RevocationURL: pointer.ToString(baseAuth + "/revoke"),
			Scopes: pointer.To([]string{
				"profile",
			}),
			UsePKCE: pointer.ToBool(true),
		},

		UserInfoURL: pointer.ToString(apiBase + "/v1.2/me"),
	}
}

// NewWithOptions creates a new Uber OAuth2 provider with defaults (supports sandbox via domain)
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	domain := ""
	if providerConfig.ExtraConfig != nil {
		if val, ok := (*providerConfig.ExtraConfig)["domain"]; ok {
			domain = val
		}
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildUberDefaults(domain))
}

// GetUserInfoEndpoint returns Uber's profile info endpoint for given domain (prod or sandbox).
func GetUserInfoEndpoint(domain string) string {
	apiBase := "https://api.uber.com"
	if domain == "sandbox-login.uber.com" {
		apiBase = "https://sandbox-api.uber.com"
	}
	return apiBase + "/v1.2/me"
}
