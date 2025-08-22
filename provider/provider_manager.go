package oauthgoprovidermanager

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/zekith/oauthgo/core/cookie"
	oauthgoprovider "github.com/zekith/oauthgo/core/provider"
	"github.com/zekith/oauthgo/core/provider/oauth2"
	"github.com/zekith/oauthgo/core/store"
	"github.com/zekith/oauthgo/core/utils"
)

// CallbackHandler is a handler that processes the OAuth2/OIDC provider's callback after login.
const (
	httpInternalServerError = 500
	successResponseHTML     = "<html><body><h3>Login successful</h3><p>You can close this window.</p></body></html>"
	htmlContentType         = "text/html; charset=utf-8"
)

// ProviderManager is a simple HTTP handler manager for OAuth2/OIDC providers.
type ProviderManager struct {
	Providers map[string]oauthgoprovider.OAuthO2IDCProvider
}

func NewProviderManager() *ProviderManager {
	return &ProviderManager{
		Providers: make(map[string]oauthgoprovider.OAuthO2IDCProvider),
	}
}

// LoginHandler is a handler that redirects the user to the OAuth2/OIDC provider's login page.
func (m *ProviderManager) LoginHandler(getOpts func(r *http.Request) oauthgoauth2.AuthURLOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get the provider from the URL path
		p, ok := m.getProviderFromPath(w, r)
		// if the provider doesn't exist, return 404
		if !ok {
			return
		}
		// get provider auth URL
		url, _, err := p.AuthURL(r.Context(), r, getOpts(r))
		// if there was an error, return 500
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// redirect to the provider's login page
		http.Redirect(w, r, url, http.StatusFound)
	}
}

// writeSuccessResponse writes a successful login response to the client
func (m *ProviderManager) writeSuccessResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", htmlContentType)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(successResponseHTML))
	return err
}

func (m *ProviderManager) CallbackHandler(cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get the provider from the URL path
		p, ok := m.getProviderFromPath(w, r)
		if !ok {
			return
		}
		// get the code and state from the request
		code := r.FormValue("code")
		state := r.FormValue("state")

		// exchange the code for a session and user info
		sess, err := p.Exchange(r.Context(), r, code, state)
		// if there was an error, return 500
		if err != nil {
			http.Error(w, err.Error(), httpInternalServerError)
			return
		}
		// get user info
		u, err := p.UserInfo(r.Context(), sess.AccessToken, sess.IDToken)
		if err != nil {
			http.Error(w, err.Error(), httpInternalServerError)
			return
		}

		cs := oauthgocookie.CookieSession{
			Provider: sess.Provider,
			Subject:  u.Subject,
			Email:    u.Email,
			Name:     u.Name,
			Expiry:   time.Now().Add(cookieMgr.TTL),
		}
		if err := cookieMgr.Set(w, cs); err != nil {
			fmt.Println("Error setting cookie:", err)
			http.Error(w, err.Error(), 500)
			return
		}

		sid := oauthgoutils.MustRandom(24)
		sessionData := oauthgostore.SessionData{
			Provider:     sess.Provider,
			Subject:      u.Subject,
			Email:        u.Email,
			Name:         u.Name,
			AccessToken:  sess.AccessToken,
			RefreshToken: sess.RefreshToken,
			Expiry:       sess.Expiry,
			CreatedAt:    time.Now(),
		}
		err = sessionStore.Put(r.Context(), sid, sessionData, 24*time.Hour)

		if err != nil {
			fmt.Println("Error storing session data:", err)
			http.Error(w, "Failed to store session data", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     env("SID_COOKIE", "oauthgo_sid"),
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err = w.Write([]byte("<html><body><h3>Login successful</h3><p>Cookie set. <a href='/me'>View profile</a> | <a href='/logout'>Logout</a> | <a href='/logout-and-revoke'>Logout & Revoke</a></p></body></html>"))
		if err != nil {
			panic(err)
			return
		}
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// DefaultRedirectURL returns a default redirect URL based on the request's scheme and host.
func DefaultRedirectURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// return the default redirect URL
	return scheme + "://" + r.Host + "/callback/" + path.Base(r.URL.Path)
}

// getProviderFromPath extracts provider name from URL path and returns the provider
func (m *ProviderManager) getProviderFromPath(w http.ResponseWriter, r *http.Request) (oauthgoprovider.OAuthO2IDCProvider, bool) {
	// split the path into provider name and remaining path
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// if the path is empty or doesn't contain a provider name, return 404
	if len(parts) < 2 {
		http.NotFound(w, r)
		return nil, false
	}

	// get the provider name
	providerName := parts[1]
	// check if the provider exists
	p, ok := m.Providers[providerName]
	// if the provider doesn't exist, return 404
	if !ok {
		http.NotFound(w, r)
		return nil, false
	}
	// return the provider
	return p, true
}
