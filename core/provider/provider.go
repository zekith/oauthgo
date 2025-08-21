package oauthgoprovider

import (
	"context"
	"net/http"
	"time"

	"github.com/zekith/oauthgo/core/types"
)

// AuthOptions are the options for generating an authentication URL.
type AuthOptions struct {
	RedirectURL string
	Scopes      []string
	Prompt      string
	LoginHint   string
	UsePKCE     bool
	Extras      map[string]string
}

// Session represents an OAuth2 session containing an access token, refresh token, and ID token.
type Session struct {
	Provider     string
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	Expiry       time.Time
	Raw          map[string]any
}

// User represents details that can be extracted from an ID token.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	Locale        *oauthgotypes.Locale
	Attributes    map[string]string
	RawProfile    map[string]any
}

// Provider is an OAuth2 provider that needs to be implemented by a provider.
type Provider interface {
	// AuthURL returns the URL to redirect the user to for authentication.
	AuthURL(ctx context.Context, r *http.Request, opts AuthOptions) (url string, opaqueState string, err error)
	// Exchange exchanges an authorization code for an access token.
	Exchange(ctx context.Context, r *http.Request, code string, opaqueState string) (*Session, error)
	// Refresh refreshes an access token.
	Refresh(ctx context.Context, refreshToken string) (*Session, error)
	// UserInfo returns the user information.
	UserInfo(ctx context.Context, accessToken, idToken string) (*User, error)
	// Revoke revokes a token.
	Revoke(ctx context.Context, token string) error
	// Name returns the name of the provider.
	Name() string
}
