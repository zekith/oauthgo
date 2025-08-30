package oauthgoxero

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Xero OAuth2 Provider Configuration
//
// Notes:
// - Xero supports OAuth2 with OpenID Connect extensions.
// - Refresh tokens are issued if `offline_access` is requested.
// - Access tokens expire in 30 minutes, so refresh handling is mandatory.
// - Use /connections to identify which Xero organisation the user has linked.
var xeroDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("xero"),
	Mode: pointer.To(oauthgotypes.OIDC), // Xero supports OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://login.xero.com/identity/connect/authorize"),
		TokenURL:      pointer.ToString("https://identity.xero.com/connect/token"),
		RevocationURL: pointer.ToString("https://identity.xero.com/connect/revocation"),
		Scopes: pointer.To([]string{
			"openid",
			"profile",
			"email",
			"offline_access",
			"accounting.transactions",
			"accounting.contacts",
		}),
		UsePKCE: pointer.ToBool(true),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:           pointer.ToString("https://identity.xero.com"),
		UserInfoURL:      pointer.ToString("https://identity.xero.com/connect/userinfo"),
		JWKSURL:          pointer.ToString("https://identity.xero.com/.well-known/openid-configuration/jwks"),
		Scopes:           pointer.To([]string{"openid", "profile", "email", "offline_access"}),
		DisableDiscovery: pointer.ToBool(false), // Discovery supported
	},
}

// NewWithOptions creates a new Xero OAuth2/OIDC provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, xeroDefaults)
}

// GetUserInfoEndpoint returns Xero's UserInfo endpoint
func GetUserInfoEndpoint() string {
	if xeroDefaults.OIDC.UserInfoURL != nil {
		return *xeroDefaults.OIDC.UserInfoURL
	}
	return ""
}
