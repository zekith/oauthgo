package oauthgo

import (
	"net/http"

	oauthgoauth2 "github.com/zekith/oauthgo/core/provider/oauth2"
	oidccore "github.com/zekith/oauthgo/core/provider/oidc"
)

// Re-export types for public use so that users don't have to import the internal packages.

type AuthURLOptions = oauthgoauth2.AuthURLOptions
type SessionData = oauthgoauth2.OAuth2Session
type User = oidccore.User

// CallbackOptions provides options to customize the callback behavior.
type CallbackOptions struct {
	SetLoginCookie bool // set the login cookie
	SetSIDCookie   bool // to set the SID in the cookie, StoreSession needed to be set to true if this is set to true
	StoreSession   bool // store the session data in the session store if this is set to true, SessionStore must be provided
	OnSuccess      func(http.ResponseWriter, *http.Request, *CallbackResult)
	OnError        func(http.ResponseWriter, *http.Request, error)
}

// CallbackResult contains the final results of a callback.
type CallbackResult struct {
	ProviderName string
	User         *User
	Session      *SessionData
	SID          string
}
