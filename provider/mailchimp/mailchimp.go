package oauthgomailchimp

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// Mailchimp OAuth2 Provider Configuration
//
// Notes:
//   - Mailchimp uses OAuth2 Authorization Code flow (no OIDC).
//   - Refresh tokens are supported.
//   - Account metadata must be fetched first from /oauth2/metadata,
//     which provides the "dc" (data center). Use that "dc" to build the API base URL.
//   - Example flow:
//     1) Exchange code for token at /oauth2/token
//     2) Call https://login.mailchimp.com/oauth2/metadata
//     3) Use "api_endpoint" or "dc" from metadata to call Mailchimp Marketing API.
var mailchimpDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("mailchimp"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2 only, no OIDC discovery

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://login.mailchimp.com/oauth2/authorize"),
		TokenURL:      pointer.ToString("https://login.mailchimp.com/oauth2/token"),
		RevocationURL: nil, // Mailchimp does not expose a standard revocation endpoint
		Scopes: pointer.To([]string{
			"audience_read",
			"campaign_read",
		}),
		UsePKCE: pointer.ToBool(true),
	},
	UserInfoURL: pointer.ToString("https://login.mailchimp.com/oauth2/metadata"),
}

// NewWithOptions creates a new Mailchimp OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, mailchimpDefaults)
}

// GetUserInfoEndpoint returns Mailchimp's metadata endpoint
// Note: After fetching metadata, use the returned "dc" to call https://<dc>.api.mailchimp.com/3.0/
func GetUserInfoEndpoint() string {
	if mailchimpDefaults.UserInfoURL != nil {
		return *mailchimpDefaults.UserInfoURL
	}
	return ""
}
