package oauthgoatlassian

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

// OAuth2 defaults for Atlassian (Jira/Confluence 3LO)
// Atlassian uses OAuth2 (3LO) and does not provide full OIDC discovery or ID tokens.
// Use the /me endpoint to retrieve the current user.
var atlassianDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("atlassian"),
	Mode: pointer.To(oauthgotypes.OAuth2Only), // OAuth2-only (no OIDC/JWKS)

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://auth.atlassian.com/authorize"),
		TokenURL:      pointer.ToString("https://auth.atlassian.com/oauth/token"),
		RevocationURL: pointer.ToString("https://auth.atlassian.com/oauth/revoke"),
		Scopes: pointer.To([]string{
			"offline_access", // for refresh tokens
			"read:jira-user", // example: read user info in Jira
			"read:me",        // example: read user info in an Atlassian account
		}),
		UsePKCE: pointer.ToBool(true), // PKCE is supported & recommended
		ExtraAuth: pointer.To(map[string]string{
			"audience": "api.atlassian.com", // required to obtain Atlassian cloud platform tokens
		}),
	},

	// No OIDC section for Atlassian
	OIDC: nil,

	// Atlassian's identity endpoint (UserInfo equivalent)
	UserInfoURL: pointer.ToString("https://api.atlassian.com/me"),
}

// NewWithOptions creates a new Atlassian OAuth2 provider with defaults
func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, atlassianDefaults)
}

// GetUserInfoEndpoint returns Atlassian's /me endpoint
func GetUserInfoEndpoint() string {
	if atlassianDefaults.UserInfoURL != nil {
		return *atlassianDefaults.UserInfoURL
	}
	return ""
}
