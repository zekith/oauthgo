package oauthgoprovider

import (
	"context"
	"net/http"

	"github.com/zekith/oauthgo/core/provider/oauth2"
	"github.com/zekith/oauthgo/core/provider/oidc"
)

// Provider represents an OAuth2 provider with optional OIDC capabilities.
type Provider interface {
	// Name returns the name of the provider.
	Name() string
	// AuthURL returns the URL to redirect the user to for authentication.
	AuthURL(ctx context.Context, r *http.Request, opts oauthgoauth2.AuthOptions) (string, string, error)
	// Exchange exchanges an authorization code for an access token.
	Exchange(ctx context.Context, r *http.Request, code, opaqueState string) (*oauthgoauth2.Session, error)
	// Refresh refreshes an access token.
	Refresh(ctx context.Context, refreshToken string) (*oauthgoauth2.Session, error)
	// Revoke revokes a token.
	Revoke(ctx context.Context, token string) error
	// UserInfo retrieves user information.
	UserInfo(ctx context.Context, accessToken, idToken string) (*oauthgooidc.User, error)
	// VerifyIDToken verifies the JWT ID token.
	VerifyIDToken(ctx context.Context, rawIDToken string) error
}

// AuthFacade is a facade for the authorisation and identity providers.
type AuthFacade struct {
	authorisationProvider oauthgoauth2.AuthorisationProvider
	identityProvider      oauthgooidc.IdentityProvider // nil for OAuth2-only providers
}

// NewAuthFacade creates a new AuthFacade.
func NewAuthFacade(authorisationProvider oauthgoauth2.AuthorisationProvider, identityProvider oauthgooidc.IdentityProvider) *AuthFacade {
	return &AuthFacade{authorisationProvider: authorisationProvider, identityProvider: identityProvider}
}

// Name returns the name of the provider.
func (f *AuthFacade) Name() string { return f.authorisationProvider.Name() }

// AuthURL returns the URL to redirect the user to for authentication.
func (f *AuthFacade) AuthURL(ctx context.Context, r *http.Request, opts oauthgoauth2.AuthOptions) (string, string, error) {
	return f.authorisationProvider.AuthURL(ctx, r, opts)
}

// Exchange exchanges an authorization code for an access token.
func (f *AuthFacade) Exchange(ctx context.Context, r *http.Request, code, state string) (*oauthgoauth2.Session, error) {
	return f.authorisationProvider.Exchange(ctx, r, code, state)
}

// Refresh refreshes an access token.
func (f *AuthFacade) Refresh(ctx context.Context, refreshToken string) (*oauthgoauth2.Session, error) {
	return f.authorisationProvider.Refresh(ctx, refreshToken)
}

// Revoke revokes a token.
func (f *AuthFacade) Revoke(ctx context.Context, token string) error {
	return f.authorisationProvider.Revoke(ctx, token)
}

// UserInfo retrieves user information.
func (f *AuthFacade) UserInfo(ctx context.Context, accessToken, idToken string) (*oauthgooidc.User, error) {
	if f.identityProvider == nil {
		return &oauthgooidc.User{}, nil
	}
	return f.identityProvider.UserInfo(ctx, accessToken, idToken)
}

// VerifyIDToken verifies the JWT ID token.
func (f *AuthFacade) VerifyIDToken(ctx context.Context, rawIDToken string) error {
	if f.identityProvider == nil {
		return nil
	}
	return f.identityProvider.VerifyIDToken(ctx, rawIDToken)
}
