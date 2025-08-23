package oauthgo

import (
	"net/http"

	oauthgocookie "github.com/zekith/oauthgo/core/cookie"
	oauthgostore "github.com/zekith/oauthgo/core/store"
)

// HandlerFacade allows wiring up handler routes like /auth/:provider and /callback/:provider.
type HandlerFacade struct {
	provider string
}

func (h *HandlerFacade) Login(getOpts func(r *http.Request) AuthURLOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url, _, err := AuthURL(h.provider, r, getOpts(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, url, http.StatusFound)
	}
}

func (h *HandlerFacade) Callback(opts CallbackOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := Callback(h.provider, w, r, opts)
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

func (h *HandlerFacade) Me(cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Me(w, r, cookieMgr, sessionStore)
	}
}

func (h *HandlerFacade) Logout(cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		Logout(w, r, cookieMgr, sessionStore)
	}
}
