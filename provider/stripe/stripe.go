package oauthgostripe

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Stripe OAuth2 Provider Configuration
//
//	Important Notes:
//
// - Stripe always uses the same domain: https://connect.stripe.com
// - The environment (test vs live) is determined by which Client ID and Secret you use:
//   - Test mode → use client_id starting with "ca_test_" and secret key "sk_test_..."
//   - Live mode → use client_id starting with "ca_live_" and secret key "sk_live_..."
//   - Sandbox installs (if "sandbox_install_compatible": true in stripe-app.json) also
//     happen via https://connect.stripe.com, but they run in a managed sandbox context.
//     No separate domain is needed.
var stripeDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("stripe"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Stripe uses OAuth2 only (no OIDC discovery)

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://connect.stripe.com/oauth/authorize"),
		TokenURL:      pointer.ToString("https://connect.stripe.com/oauth/token"),
		RevocationURL: pointer.ToString("https://connect.stripe.com/oauth/deauthorize"),
		Scopes: pointer.To([]string{
			"read_write", // full access (you may also use "read_only")
		}),
		UsePKCE: pointer.ToBool(false), // Stripe requires client_secret, PKCE not supported
	},

	UserInfoURL: pointer.ToString("https://api.stripe.com/v1/accounts"),
}

// NewWithOptions creates a new Stripe OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, stripeDefaults)
}

// GetUserInfoEndpoint returns Stripe's account info endpoint
func GetUserInfoEndpoint() string {
	if stripeDefaults.UserInfoURL != nil {
		return *stripeDefaults.UserInfoURL
	}
	return ""
}
