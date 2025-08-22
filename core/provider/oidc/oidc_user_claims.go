package oauthgooidc

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/zekith/oauthgo/core/types"
)

// OIDCUserClaims represents typical OIDC user claims including registered claims.
type OIDCUserClaims struct {
	jwt.RegisteredClaims
	//Email is the user's email address.
	Email string `json:"email"`
	//EmailVerified indicates whether the user's email address has been verified.
	EmailVerified oauthgotypes.BoolString `json:"email_verified"`
	//Name is the user's full name.
	Name string `json:"name"`
	// GivenName is the user's first name.
	GivenName string `json:"given_name"`
	// FamilyName is the user's last name.
	FamilyName string `json:"family_name"`
	// Picture is the URL of the user's profile picture.
	Picture string `json:"picture"`
	// Locale is the user's locale, which can be a string or an object.
	Locale *oauthgotypes.Locale `json:"locale"` // supports string or object via custom unmarshal
}

// GetExpirationTime returns the expiration time of the token.
func (c *OIDCUserClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.ExpiresAt, nil
}

// GetIssuedAt returns the issued at time of the token.
func (c *OIDCUserClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.IssuedAt, nil
}

// GetNotBefore returns the not before time of the token.
func (c *OIDCUserClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.NotBefore, nil
}

// GetIssuer returns the issuer of the token.
func (c *OIDCUserClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject returns the subject of the token.
// The subject is typically the unique identifier for the user in the OIDC context.
func (c *OIDCUserClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// GetAudience returns the audience of the token.
// The audience is typically the client ID of the application that the token is intended for.
func (c *OIDCUserClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

// ToUser converts OIDCUserClaims to a User.
func (c *OIDCUserClaims) ToUser() *User {
	return &User{
		Subject:       c.Subject,
		Email:         c.Email,
		EmailVerified: bool(c.EmailVerified), // convert back to plain bool
		Name:          c.Name,
		GivenName:     c.GivenName,
		FamilyName:    c.FamilyName,
		Picture:       c.Picture,
		Locale:        c.Locale,
	}
}
