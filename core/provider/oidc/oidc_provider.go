package oauthgooidc

import (
	"context"

	oauthgotypes "github.com/zekith/oauthgo/core/types"
)

// User represents details that can be extracted from an ID token.
type User struct {
	Subject       string               `json:"sub"`
	Email         string               `json:"email"`
	EmailVerified bool                 `json:"email_verified"`
	Name          string               `json:"name"`
	GivenName     string               `json:"given_name"`
	FamilyName    string               `json:"family_name"`
	Picture       string               `json:"picture"`
	Locale        *oauthgotypes.Locale `json:"locale"`
	Attributes    map[string]string    `json:"attributes"`
	RawProfile    map[string]any       `json:"raw_profile"`
}

// OIDCProvider Identity-only surface (OIDC or custom profile).
type OIDCProvider interface {
	// UserInfo returns the user details.
	UserInfo(ctx context.Context, accessToken, idToken string) (*User, error)
	// VerifyIDToken verifies the JWT ID token.
	VerifyIDToken(ctx context.Context, rawIDToken string) error
}
