package oauthgopaypal

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// PayPal OAuth2 Provider Configuration
//
//	Notes:
//
// - Sandbox vs Live is determined by which endpoints you use.
// - Sandbox: https://api-m.sandbox.paypal.com
// - Live:    https://api-m.paypal.com
// - Auth endpoints differ slightly for sandbox vs live.
func buildPayPalDefaults(isSandbox bool) *oauthgotypes.OAuth2OIDCOptions {
	baseAuth := "https://www.paypal.com/signin/authorize"
	baseAPI := "https://api-m.paypal.com"
	if isSandbox {
		baseAuth = "https://www.sandbox.paypal.com/signin/authorize"
		baseAPI = "https://api-m.sandbox.paypal.com"
	}

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("paypal"),
		Mode: pointer.To(oauthgotypes.OAuth2Only), // PayPal supports OAuth2, not OIDC discovery

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:  pointer.ToString(baseAuth),
			TokenURL: pointer.ToString(baseAPI + "/v1/oauth2/token"),
			// PayPal does not expose a standard RFC7009 revocation endpoint
			Scopes: pointer.To([]string{
				"openid",
				"profile",
				"email",
				"https://uri.paypal.com/services/paypalattributes",
			}),
			UsePKCE: pointer.ToBool(false), // PayPal uses client_secret for token exchange
		},

		UserInfoURL: pointer.ToString(baseAPI + "/v1/identity/openidconnect/userinfo/?schema=openid"),
	}
}

// NewWithOptions creates a new PayPal OAuth2 provider with defaults.
// Use ExtraConfig["sandbox"] = "true" to toggle sandbox endpoints.
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	isSandbox := false
	if providerConfig.ExtraConfig != nil {
		if val, ok := (*providerConfig.ExtraConfig)["sandbox"]; ok && val == "true" {
			isSandbox = true
		}
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildPayPalDefaults(isSandbox))
}

// GetUserInfoEndpoint returns PayPal's user info endpoint (sandbox or live)
func GetUserInfoEndpoint(isSandbox bool) string {
	if isSandbox {
		return "https://api-m.sandbox.paypal.com/v1/identity/openidconnect/userinfo/?schema=openid"
	}
	return "https://api-m.paypal.com/v1/identity/openidconnect/userinfo/?schema=openid"
}
