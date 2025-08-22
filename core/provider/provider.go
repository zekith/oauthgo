package oauthgoprovider

import (
	"context"
	"net/http"

	"github.com/zekith/oauthgo/core/provider/oauth2"
	"github.com/zekith/oauthgo/core/provider/oidc"
)

type Provider interface {
	Name() string
	AuthURL(ctx context.Context, r *http.Request, opts oauthgoauth2.AuthOptions) (string, string, error)
	Exchange(ctx context.Context, r *http.Request, code, opaqueState string) (*oauthgoauth2.Session, error)
	Refresh(ctx context.Context, refreshToken string) (*oauthgoauth2.Session, error)
	Revoke(ctx context.Context, token string) error
	UserInfo(ctx context.Context, accessToken, idToken string) (*oauthgooidc.User, error)
}

type AuthFacade struct {
	authorisationProvider oauthgoauth2.AuthorisationProvider
	identityProvider      oauthgooidc.IdentityProvider // nil for OAuth2-only providers
}

func NewAuthFacade(authorisationProvider oauthgoauth2.AuthorisationProvider, identityProvider oauthgooidc.IdentityProvider) *AuthFacade {
	return &AuthFacade{authorisationProvider: authorisationProvider, identityProvider: identityProvider}
}

func (f *AuthFacade) Name() string { return f.authorisationProvider.Name() }

func (f *AuthFacade) AuthURL(ctx context.Context, r *http.Request, opts oauthgoauth2.AuthOptions) (string, string, error) {
	return f.authorisationProvider.AuthURL(ctx, r, opts)
}
func (f *AuthFacade) Exchange(ctx context.Context, r *http.Request, code, state string) (*oauthgoauth2.Session, error) {
	return f.authorisationProvider.Exchange(ctx, r, code, state)
}
func (f *AuthFacade) Refresh(ctx context.Context, refreshToken string) (*oauthgoauth2.Session, error) {
	return f.authorisationProvider.Refresh(ctx, refreshToken)
}
func (f *AuthFacade) Revoke(ctx context.Context, token string) error {
	return f.authorisationProvider.Revoke(ctx, token)
}
func (f *AuthFacade) UserInfo(ctx context.Context, accessToken, idToken string) (*oauthgooidc.User, error) {
	if f.identityProvider == nil {
		return &oauthgooidc.User{}, nil
	}
	return f.identityProvider.UserInfo(ctx, accessToken, idToken)
}
