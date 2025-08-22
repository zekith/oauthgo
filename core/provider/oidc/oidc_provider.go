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

// OIDCProvider Identity-only surface (OIDC or custom profile).
type OIDCProvider interface {
	// UserInfo returns the user details.
	UserInfo(ctx context.Context, accessToken, idToken string) (*User, error)
	// VerifyIDToken verifies the JWT ID token.
	VerifyIDToken(ctx context.Context, rawIDToken string) error
}
