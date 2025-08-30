package oauthgoshopify

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// buildShopifyDefaults builds the Shopify provider config for a given shop domain.
// Example shop domain: "my-store.myshopify.com"
func buildShopifyDefaults(shop string) *oauthgotypes.OAuth2OIDCOptions {
	if shop == "" {
		shop = "zekithtest.myshopify.com" // fallback placeholder
	}
	baseAuth := fmt.Sprintf("https://%s/admin/oauth/authorize", shop)
	baseToken := fmt.Sprintf("https://%s/admin/oauth/access_token", shop)

	return &oauthgotypes.OAuth2OIDCOptions{
		Name: pointer.ToString("shopify"),
		Mode: pointer.To(oauthgotypes.OAuth2Only), // Shopify supports OAuth2 only (no OIDC discovery)

		OAuth2: &oauthgotypes.OAuth2Options{
			AuthURL:       pointer.ToString(baseAuth),
			TokenURL:      pointer.ToString(baseToken),
			RevocationURL: nil, // Shopify does not support RFC7009 revocation
			Scopes: pointer.To([]string{
				"read_products",
				"write_products",
				"read_orders",
				"write_orders",
			}),
			UsePKCE: pointer.ToBool(false), // Shopify requires client_secret, not PKCE
		},
		UserInfoURL: pointer.ToString(fmt.Sprintf("https://%s/admin/api/2025-07/users/current.json", shop)),
	}
}

// NewWithOptions creates a new Shopify OAuth2 provider for a given shop domain.
// You must pass providerConfig.ExtraConfig["shop"] = "my-store.myshopify.com"
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	shop := ""
	if providerConfig.ExtraConfig != nil {
		if val, ok := (*providerConfig.ExtraConfig)["shop"]; ok {
			shop = val
		}
	}
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, buildShopifyDefaults(shop))
}

// GetUserInfoEndpoint returns Shopify's shop info endpoint for a given shop.
func GetUserInfoEndpoint(shop string) string {
	if shop == "" {
		shop = "zekithtest.myshopify.com" // fallback placeholder
	}
	return fmt.Sprintf("https://%s/admin/api/2024-07/shop.json", shop)
}
