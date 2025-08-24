package oauthgocookie

import (
	"net/http"
	"time"
)

// SessionCookieManager is an interface for managing session cookies.
type SessionCookieManager interface {
	Set(w http.ResponseWriter, s SessionCookiePayload) error
	Clear(w http.ResponseWriter)
	Parse(r *http.Request) (*SessionCookiePayload, bool)
	Expiry() time.Duration
}

// SessionCookiePayload is the payload of the session cookie.
type SessionCookiePayload struct {
	// Provider is the name of the OAuth provider e.g. "google"
	Provider string `json:"provider"`
	// Subject is the user's unique identifier
	Subject string `json:"sub"`
	// Email is the user's email address
	Email string `json:"email"`
	// Name is the user's full name
	Name string `json:"name"`
	// Expiry is the time when the session expires
	Expiry time.Time `json:"exp"`
}
