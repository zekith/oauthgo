package oauthgosquare

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildSquareDefaults builds a Square OAuth2/OIDC config for the given domain.
// Example domains:
//   - "connect.squareup.com" (production)
//   - "connect.squareupsandbox.com" (sandbox)
func buildSquareDefaults(domain string) *oauthgotypes.OAuth2OIDCOptions {
	baseURL := fmt.Sprintf("https://%s", domain)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("square"),
		Mode: pointer.To(oauthgotypes.OAuth2Only), // Square supports OAuth2, not full OIDC discovery

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(baseURL + "/oauth2/authorize"),
			TokenURL:      pointer.ToString(baseURL + "/oauth2/token"),
			RevocationURL: pointer.ToString(baseURL + "/oauth2/revoke"),
			Scopes: pointer.To([]string{
				"MERCHANT_PROFILE_READ",
			}),
			UsePKCE: pointer.ToBool(false),
			ExtraAuth: pointer.To(map[string]string{
				"session": "true",
			}),
		},
		UserInfoURL: pointer.ToString(baseURL + "/v2/merchants/me"),
	}
}

// NewWithOptions creates a new Square OAuth2/OIDC provider with defaults for the given domain
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	domain := "connect.squareup.com" // default production

	if providerConfig.ExtraConfig != nil {
		result, ok := pointer.Get(providerConfig.ExtraConfig)["domain"]

		if ok {
			domain = result
		}
	}

	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildSquareDefaults(domain))
}

// GetUserInfoEndpoint returns Square's merchant info endpoint for the given domain
func GetUserInfoEndpoint(domain string) string {
	return fmt.Sprintf("https://%s/v2/merchants/me", domain)
}
