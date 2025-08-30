package oauthgonotion

import (
	"github.com/AlekSi/pointer"
	oauthgofactory "github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// OAuth2/OIDC defaults for Notion
var notionDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("notion"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // Notion supports OAuth2, not OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://api.notion.com/v1/oauth/authorize"),
		TokenURL:      pointer.ToString("https://api.notion.com/v1/oauth/token"),
		RevocationURL: nil,                    // Notion does not provide a standard revocation endpoint
		Scopes:        pointer.To([]string{}), // Notion doesn’t use explicit scopes; access is tied to integration capabilities
		UsePKCE:       pointer.ToBool(false),  // Notion uses client_id + client_secret (Basic Auth) for token exchange
	},
	UserInfoURL: pointer.ToString("https://api.notion.com/v1/users/me"),
}

// NewWithOptions creates a new Notion OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, notionDefaults)
}

// GetUserInfoEndpoint returns Notion's user info endpoint (/v1/users/me)
func GetUserInfoEndpoint() string {
	if notionDefaults.UserInfoURL != nil {
		return *notionDefaults.UserInfoURL
	}
	return ""
}
