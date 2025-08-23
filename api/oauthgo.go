package oauthgo

import (
	"fmt"
	"net/http"

	oauthgobootstrap "github.com/zekith/oauthgo/core/bootstrap"
	oauthgocookie "github.com/zekith/oauthgo/core/cookie"
	oauthgoauth2 "github.com/zekith/oauthgo/core/provider/oauth2"
	"github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgostore "github.com/zekith/oauthgo/core/store"
)

// Publicly exposed manager instance
var providerManager = NewProviderManager()

// Register registers an OAuth2/OIDC provider by name.
func Register(name string, provider oauth2oidc.OAuthO2IDCProvider) {
	providerManager.Register(name, provider)
}

// AuthURL generates the authorization URL for a given provider.
func AuthURL(providerName string, r *http.Request, opts AuthURLOptions) (string, string, error) {
	return providerManager.AuthURL(providerName, r, opts)
}

// Callback processes the OAuth2/OIDC callback and returns the session + user info.
func Callback(providerName string, w http.ResponseWriter, r *http.Request, opts CallbackOptions) (*CallbackResult, error) {
	return providerManager.Callback(providerName, w, r, opts)
}

func Me(w http.ResponseWriter, r *http.Request, cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) {
	providerManager.Me(w, r, cookieMgr, sessionStore)
}

func Logout(w http.ResponseWriter, r *http.Request, cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) {
	providerManager.Logout(w, r, cookieMgr, sessionStore)
}

// Handle returns a struct that can be used to wire auth and callback handlers easily.
func Handle(providerName string) *HandlerFacade {
	return &HandlerFacade{
		provider: providerName,
	}
}

func MeHandler(providerName string, core *oauthgobootstrap.Core) http.HandlerFunc {
	return Handle(providerName).Me(core.CookieMgr, core.SessionStore)
}

func LogoutHandler(providerName string, core *oauthgobootstrap.Core) http.HandlerFunc {
	return Handle(providerName).Logout(core.CookieMgr, core.SessionStore)
}

// AutoLogin returns a standard login handler for given provider
func AutoLogin(providerName string) http.HandlerFunc {
	return Handle(providerName).Login(func(r *http.Request) oauthgoauth2.AuthURLOptions {
		return oauthgoauth2.AuthURLOptions{
			RedirectURL: fmt.Sprintf("http://%s/callback/%s", r.Host, providerName),
		}
	})
}

// AutoCallbackOIDC returns a callback handler with default settings for OIDC
func AutoCallbackOIDC(providerName string, core *oauthgobootstrap.Core) http.HandlerFunc {
	return Handle(providerName).Callback(CallbackOptions{
		CookieManager:  core.CookieMgr,
		SessionStore:   core.SessionStore,
		SetLoginCookie: true,
		SetSIDCookie:   true,
		StoreSession:   true,
		OnSuccess: func(w http.ResponseWriter, r *http.Request, res *CallbackResult) {
			_, _ = w.Write([]byte("Login success for " + providerName + ": " + res.User.Email))
		},
	})
}

// AutoCallbackOAuth2 returns a callback handler with default settings for OAuth2
func AutoCallbackOAuth2(providerName string, core *oauthgobootstrap.Core) http.HandlerFunc {
	return Handle(providerName).Callback(CallbackOptions{
		OnSuccess: func(w http.ResponseWriter, r *http.Request, res *CallbackResult) {
			_, _ = w.Write([]byte("Login success for " + providerName + ": " + res.User.Email))
		},
	})
}
