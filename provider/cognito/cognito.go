package oauthgocognito

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildCognitoDefaults builds the Cognito provider config for a given domain, region, and userPoolId.
//
// Example domain: "myapp" (for myapp.auth.us-east-1.amazoncognito.com)
// Example region: "us-east-1"
// Example userPoolId: "us-east-1_AbCdEf123"
func buildCognitoDefaults(domain, region, userPoolId string) *oauthgotypes.OAuth2OIDCOptions {
	if domain == "" || region == "" || userPoolId == "" {
		panic("cognito: domain, region, and userPoolId are required")
	}

	baseAuthURL := fmt.Sprintf("https://%s.auth.%s.amazoncognito.com/oauth2", domain, region)
	issuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId)
	jwks := fmt.Sprintf("%s/.well-known/jwks.json", issuer)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("cognito"),
		Mode: pointer.To(oauthgotypes.OIDC), // Cognito is OIDC-compliant

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(baseAuthURL + "/authorize"),
			TokenURL:      pointer.ToString(baseAuthURL + "/token"),
			RevocationURL: nil, // Cognito does not expose RFC7009 revocation
			Scopes: pointer.To([]string{
				"openid",
				"profile",
				"email",
			}),
			UsePKCE: pointer.ToBool(true),
		},
		OIDC: &oauthgotypes.OIDCOptions{
			Issuer:           pointer.ToString(issuer),
			UserInfoURL:      pointer.ToString(baseAuthURL + "/userinfo"),
			JWKSURL:          pointer.ToString(jwks),
			DisableDiscovery: pointer.ToBool(true), // manual config, avoid relying on discovery
			Scopes: pointer.To([]string{
				"openid",
				"profile",
				"email",
			}),
		},
	}
}

// NewWithOptions creates a new Cognito OAuth2/OIDC provider for the given domain/region/userPoolId.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	var domain, region, userPoolId string

	if providerConfig.ExtraConfig != nil {
		if d, ok := (*providerConfig.ExtraConfig)["domain"]; ok {
			domain = d
		}
		if r, ok := (*providerConfig.ExtraConfig)["region"]; ok {
			region = r
		}
		if u, ok := (*providerConfig.ExtraConfig)["userPoolId"]; ok {
			userPoolId = u
		}
	}

	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildCognitoDefaults(domain, region, userPoolId))
}

// GetUserInfoEndpoint returns Cognito's userInfo endpoint for the given domain and region.
// Note: this requires passing the same domain/region used in buildCognitoDefaults.
func GetUserInfoEndpoint(domain, region string) string {
	return fmt.Sprintf("https://%s.auth.%s.amazoncognito.com/oauth2/userinfo", domain, region)
}
