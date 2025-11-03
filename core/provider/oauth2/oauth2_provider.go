package oauthgoauth2

import (
	"context"
	"net/http"
	"time"

	oauthgostate "github.com/zekith/oauthgo/core/state"
)

// AuthURLOptions are the options for generating an authentication URL.
type AuthURLOptions struct {
	RedirectURL string            // Redirect URL after authentication
	ReturnTo    string            // ReturnTo URL after authentication
	Scopes      []string          // Scopes to request
	Prompt      string            // Prompt to use
	LoginHint   string            // Login hint to use
	Extras      map[string]string // Additional parameters to include in the URL
}

// OAuth2Session represents an OAuth2 session containing an access token, refresh token, and ID token.
type OAuth2Session struct {
	Provider     string         `json:"provider"`      // Required
	AccessToken  string         `json:"access_token"`  // Required
	RefreshToken string         `json:"refresh_token"` // Present if the provider supports refresh tokens
	IDToken      string         `json:"id_token"`      // optional; empty in pure OAuth2
	TokenType    string         `json:"token_type"`    // Access token type
	Expiry       time.Time      `json:"expiry"`        // Expiry time of the access token
	Raw          map[string]any `json:"raw"`           // Raw token data
}

// OAuth2Provider is an OAuth2 provider that needs to be implemented by a provider.
type OAuth2Provider interface {
	// Name returns the name of the provider.
	Name() string
	// AuthURL returns the URL to redirect the user to for authentication.
	AuthURL(ctx context.Context, r *http.Request, opts AuthURLOptions) (url string, opaqueState string, err error)
	// Exchange exchanges an authorization code for an access token.
	Exchange(ctx context.Context, r *http.Request, code string, opaqueState string) (*OAuth2Session, error)
	// Refresh refreshes an access token based on a refresh token.
	Refresh(ctx context.Context, refreshToken string) (*OAuth2Session, error)
	// Revoke revokes a token.
	Revoke(ctx context.Context, token string) error
	// GetState Get state from opaque state
	GetState(ctx context.Context, opaqueState string) (*oauthgostate.StatePayload, error)
}
