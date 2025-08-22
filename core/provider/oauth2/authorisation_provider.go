package oauthgoauth2

import (
	"context"
	"net/http"
	"time"
)

// AuthOptions are the options for generating an authentication URL.
type AuthOptions struct {
	RedirectURL string
	Scopes      []string
	Prompt      string
	LoginHint   string
	Extras      map[string]string
}

// Session represents an OAuth2 session containing an access token, refresh token, and ID token.
type Session struct {
	Provider     string
	AccessToken  string
	RefreshToken string
	IDToken      string // optional; empty in pure OAuth2
	TokenType    string
	Expiry       time.Time
	Raw          map[string]any
}

// AuthorisationProvider is an OAuth2 provider that needs to be implemented by a provider.
type AuthorisationProvider interface {
	// Name returns the name of the provider.
	Name() string
	// AuthURL returns the URL to redirect the user to for authentication.
	AuthURL(ctx context.Context, r *http.Request, opts AuthOptions) (url string, opaqueState string, err error)
	// Exchange exchanges an authorization code for an access token.
	Exchange(ctx context.Context, r *http.Request, code string, opaqueState string) (*Session, error)
	// Refresh refreshes an access token.
	Refresh(ctx context.Context, refreshToken string) (*Session, error)
	// Revoke revokes a token.
	Revoke(ctx context.Context, token string) error
}
