package oauth2oidc

import (
	"context"
	"net/http"

	"github.com/zekith/oauthgo/core/provider/oauth2"
	"github.com/zekith/oauthgo/core/provider/oidc"
)

// OAuthO2IDCProvider represents an OAuth2 provider with optional OIDC capabilities.
type OAuthO2IDCProvider interface {
	// Name returns the name of the provider.
	Name() string
	// AuthURL returns the URL to redirect the user to for authentication.
	AuthURL(ctx context.Context, r *http.Request, opts oauthgoauth2.AuthURLOptions) (string, string, error)
	// Exchange exchanges an authorization code for an access token.
	Exchange(ctx context.Context, r *http.Request, code, opaqueState string) (*oauthgoauth2.OAuth2Session, error)
	// Refresh refreshes an access token.
	Refresh(ctx context.Context, refreshToken string) (*oauthgoauth2.OAuth2Session, error)
	// Revoke revokes a token.
	Revoke(ctx context.Context, token string) error
	// UserInfo retrieves user information.
	UserInfo(ctx context.Context, accessToken, idToken string) (*oauthgooidc.User, error)
	// VerifyIDToken verifies the JWT ID token.
	VerifyIDToken(ctx context.Context, rawIDToken string) error
}

// OAuth2OIDCFacade is a facade for the authorisation and identity providers.
type OAuth2OIDCFacade struct {
	oAuth2Provider oauthgoauth2.OAuth2Provider
	oidcProvider   oauthgooidc.OIDCProvider // nil for OAuth2-only providers
}
