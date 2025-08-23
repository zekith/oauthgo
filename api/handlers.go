package oauthgo

import (
	"fmt"
	"net/http"

	oauthgobootstrap "github.com/zekith/oauthgo/core/bootstrap"
	"github.com/zekith/oauthgo/core/provider/oauth2oidc"
)

// providerManager is the global provider manager.
var providerManager = NewProviderManager()

// HandlerFacade is a facade for the handlers.
type HandlerFacade struct{}

// LoggedInUser returns a handler that returns the logged-in user.
func (h *HandlerFacade) LoggedInUser(core *oauthgobootstrap.Core) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providerManager.LoggedInUser(w, r, core.CookieMgr, core.SessionStore)
	}
}

// Logout returns a handler that logs out the user.
func (h *HandlerFacade) Logout(core *oauthgobootstrap.Core) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providerManager.Logout(w, r, core.CookieMgr, core.SessionStore)
	}
}

// Login returns a handler that redirects to the provider login page.
func (h *HandlerFacade) Login(provider string, authURLOptions AuthURLOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url, _, err := providerManager.AuthURL(provider, r, authURLOptions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, url, http.StatusFound)
	}
}

// Callback returns a handler that handles the callback after the user logs in.
// The callback handler can be customized with the options.
// The OnSuccess can be used to customize the response after the user logs in.
func (h *HandlerFacade) Callback(provider string, opts CallbackOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := providerManager.Callback(provider, w, r, opts)
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(w, r, err)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		if opts.OnSuccess != nil {
			opts.OnSuccess(w, r, res)
		} else {
			_, err = w.Write([]byte("Login successful."))
			if err != nil {
				return
			}
		}
	}
}

// AutoLogin returns a handler that redirects to the login page.
// This is useful for demos and testing multiple providers.
func (h *HandlerFacade) AutoLogin(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Login(provider, AuthURLOptions{
			RedirectURL: fmt.Sprintf("http://%s/callback/%s", r.Host, provider),
		})(w, r)
	}
}

// AutoCallbackOIDC returns a handler that handles the callback for OIDC.
// This is useful for demos and testing multiple providers.
func (h *HandlerFacade) AutoCallbackOIDC(provider string, core *oauthgobootstrap.Core) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Callback(provider, CallbackOptions{
			CookieManager:  core.CookieMgr,
			SessionStore:   core.SessionStore,
			SetLoginCookie: true,
			SetSIDCookie:   true,
			StoreSession:   true,
			OnSuccess: func(w http.ResponseWriter, r *http.Request, res *CallbackResult) {
				_, _ = w.Write([]byte("Login success for " + provider + ": " + res.User.Email))
			},
		})(w, r)
	}
}

// AutoCallbackOAuth2 returns a handler that handles the callback for OAuth2.
// This is useful for demos and testing multiple providers.
func (h *HandlerFacade) AutoCallbackOAuth2(provider string, _ *oauthgobootstrap.Core) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Callback(provider, CallbackOptions{
			OnSuccess: func(w http.ResponseWriter, r *http.Request, res *CallbackResult) {
				_, _ = w.Write([]byte("Login success for " + provider + " with access token: " + res.Session.AccessToken))
			},
		})(w, r)
	}
}

// Register registers a provider.
func (h *HandlerFacade) Register(name string, provider oauth2oidc.OAuthO2IDCProvider) {
	providerManager.Register(name, provider)
}
