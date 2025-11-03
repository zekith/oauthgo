package oauth2oidc

import (
	"context"
	"net/http"

	oauthgoauth2 "github.com/zekith/oauthgo/core/provider/oauth2"
	oauthgooidc "github.com/zekith/oauthgo/core/provider/oidc"
	oauthgostate "github.com/zekith/oauthgo/core/state"
)

// NewOAuth2OIDCFacade creates a new OAuth2OIDCFacade.
func NewOAuth2OIDCFacade(oAuth2Provider oauthgoauth2.OAuth2Provider, oidcProvider oauthgooidc.OIDCProvider) *OAuth2OIDCFacade {
	return &OAuth2OIDCFacade{oAuth2Provider: oAuth2Provider, oidcProvider: oidcProvider}
}

// Name returns the name of the provider.
func (f *OAuth2OIDCFacade) Name() string { return f.oAuth2Provider.Name() }

// AuthURL returns the URL to redirect the user to for authentication.
func (f *OAuth2OIDCFacade) AuthURL(ctx context.Context, r *http.Request, opts oauthgoauth2.AuthURLOptions) (string, string, error) {
	return f.oAuth2Provider.AuthURL(ctx, r, opts)
}

// Exchange exchanges an authorization code for an access token.
func (f *OAuth2OIDCFacade) Exchange(ctx context.Context, r *http.Request, code, state string) (*oauthgoauth2.OAuth2Session, error) {
	return f.oAuth2Provider.Exchange(ctx, r, code, state)
}

// Refresh refreshes an access token.
func (f *OAuth2OIDCFacade) Refresh(ctx context.Context, refreshToken string) (*oauthgoauth2.OAuth2Session, error) {
	return f.oAuth2Provider.Refresh(ctx, refreshToken)
}

// Revoke revokes a token.
func (f *OAuth2OIDCFacade) Revoke(ctx context.Context, token string) error {
	return f.oAuth2Provider.Revoke(ctx, token)
}

// GetState Get state from opaque state
func (f *OAuth2OIDCFacade) GetState(ctx context.Context, opaqueState string) (*oauthgostate.StatePayload, error) {
	return f.oAuth2Provider.GetState(ctx, opaqueState)
}

// UserInfo retrieves user information.
func (f *OAuth2OIDCFacade) UserInfo(ctx context.Context, accessToken, idToken string) (*oauthgooidc.User, error) {
	if f.oidcProvider == nil {
		return &oauthgooidc.User{}, nil
	}
	return f.oidcProvider.UserInfo(ctx, accessToken, idToken)
}

// VerifyIDToken verifies the JWT ID token.
func (f *OAuth2OIDCFacade) VerifyIDToken(ctx context.Context, rawIDToken string) error {
	if f.oidcProvider == nil {
		return nil
	}
	return f.oidcProvider.VerifyIDToken(ctx, rawIDToken)
}
