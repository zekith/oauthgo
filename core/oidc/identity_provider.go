package oauthgooidc

import (
	"context"

	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

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

// IdentityProvider Identity-only surface (OIDC or custom profile).
type IdentityProvider interface {
	UserInfo(ctx context.Context, accessToken, idToken string) (*User, error)
	VerifyIDToken(ctx context.Context, rawIDToken string) error // no-op for pure OAuth2
}
