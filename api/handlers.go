package oauthgo

import (
	"net/http"

	"github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgoutils "github.com/zekith/oauthgo/core/utils"
)

// providerManager is the global provider manager.
var providerManager = NewProviderManager()

// HandlerFacade is a facade for the handlers.
type HandlerFacade struct{}

// LoggedInUser returns a handler that returns the logged-in user (JSON).
func (h *HandlerFacade) LoggedInUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providerManager.LoggedInUser(w, r)
	}
}

// Logout returns a handler that logs out the user.
// If ?redirect_uri=/ (or ?rd=/) is provided, it will redirect after clearing sessions.
func (h *HandlerFacade) Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providerManager.Logout(w, r)
	}
}

// Revoke returns a handler that revokes a token (JSON).
func (h *HandlerFacade) Revoke(provider string, token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := providerManager.Revoke(provider, token, r); err != nil {
			oauthgoutils.WriteError(w, http.StatusInternalServerError, "failed to revoke token", err)
			return
		}
		oauthgoutils.WriteJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"revoked": true,
		})
	}
}

// Refresh returns a handler that refreshes an access token (JSON).
func (h *HandlerFacade) Refresh(provider string, refreshToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		oAuthSession, err := providerManager.Refresh(provider, refreshToken, r)
		if err != nil {
			oauthgoutils.WriteError(w, http.StatusInternalServerError, "failed to refresh token", err)
			return
		}
		oauthgoutils.WriteJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"session": oAuthSession,
		})
	}
}

// Login returns a handler that redirects to the provider auth page by default.
// If the client prefers JSON, pass ?json=1 or ?format=json or set Accept: application/json.
func (h *HandlerFacade) Login(provider string, authURLOptions AuthURLOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url, _, err := providerManager.AuthURL(provider, r, authURLOptions)
		if err != nil {
			oauthgoutils.WriteError(w, http.StatusInternalServerError, "failed to build auth url", err)
			return
		}

		http.Redirect(w, r, url, http.StatusFound)
	}
}

// Callback returns a handler that handles the callback after the user logs in.
// Default behavior: if opts.OnSuccess is nil, redirect to ?redirect_uri (or ?rd)
// when provided; otherwise return JSON payload.
func (h *HandlerFacade) Callback(provider string, opts CallbackOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := providerManager.Callback(provider, w, r, opts)
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(w, r, err)
			} else {
				oauthgoutils.WriteError(w, http.StatusInternalServerError, "login callback failed", err)
			}
			return
		}

		// Custom hook
		if opts.OnSuccess != nil {
			opts.OnSuccess(w, r, res)
			return
		}

		// Default: redirect if the caller provided a target; else JSON.
		if redir := oauthgoutils.FirstNonEmpty(r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("rd")); redir != "" {
			http.Redirect(w, r, redir, http.StatusFound)
			return
		}

		oauthgoutils.WriteJSON(w, http.StatusOK, map[string]any{
			"status":   "ok",
			"provider": provider,
			"result":   res,
			"mode":     "json",
		})
	}
}

// AutoLogin returns a handler that redirects to the provider by default (like Login).
// If the client prefers JSON, pass ?json=1 or set Accept: application/json.
func (h *HandlerFacade) AutoLogin(baseUrl string, provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Login(provider, AuthURLOptions{
			RedirectURL: baseUrl + "/" + provider,
		})(w, r)
	}
}

// AutoCallbackOIDC returns a handler that handles the callback for OIDC.
// If ?redirect_uri=/ (or ?rd=/) is present, redirect there; else return JSON.
func (h *HandlerFacade) AutoCallbackOIDC(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Callback(provider, CallbackOptions{
			SetLoginCookie: true,
			SetSIDCookie:   true,
			StoreSession:   true,
			OnSuccess: func(w http.ResponseWriter, r *http.Request, res *CallbackResult) {
				if redir := oauthgoutils.FirstNonEmpty(r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("rd")); redir != "" {
					http.Redirect(w, r, redir, http.StatusFound)
					return
				}
				oauthgoutils.WriteJSON(w, http.StatusOK, map[string]any{
					"status":   "ok",
					"provider": provider,
					"user":     res.User,
					"sid":      res.SID,
					"session":  res.Session,
				})
			},
			OnError: func(w http.ResponseWriter, r *http.Request, err error) {
				oauthgoutils.WriteError(w, http.StatusInternalServerError, "oidc auto-callback failed", err)
			},
		})(w, r)
	}
}

// AutoCallbackOAuth2 returns a handler that handles the callback for OAuth2.
// If ?redirect_uri=/ (or ?rd=/) is present, redirect there; else return JSON.
func (h *HandlerFacade) AutoCallbackOAuth2(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h.Callback(provider, CallbackOptions{
			OnSuccess: func(w http.ResponseWriter, r *http.Request, res *CallbackResult) {
				if redirectUrl := oauthgoutils.FirstNonEmpty(r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("rd")); redirectUrl != "" {
					http.Redirect(w, r, redirectUrl, http.StatusFound)
					return
				}
				oauthgoutils.WriteJSON(w, http.StatusOK, map[string]any{
					"status":        "ok",
					"provider":      provider,
					"access_token":  res.Session.AccessToken,
					"refresh_token": res.Session.RefreshToken,
					"expiry":        res.Session.Expiry,
				})
			},
			OnError: func(w http.ResponseWriter, r *http.Request, err error) {
				oauthgoutils.WriteError(w, http.StatusInternalServerError, "oauth2 auto-callback failed", err)
			},
		})(w, r)
	}
}

// Register registers a provider.
func (h *HandlerFacade) Register(name string, provider oauth2oidc.OAuthO2IDCProvider) {
	providerManager.Register(name, provider)
}
