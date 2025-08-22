package oauthgoexampleshelper

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zekith/oauthgo/core/cookie"
	env2 "github.com/zekith/oauthgo/core/env"
	coreprovider "github.com/zekith/oauthgo/core/provider/oauth2"
	"github.com/zekith/oauthgo/core/store"
	"github.com/zekith/oauthgo/provider"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const (
	EnvSIDCookie = "SID_COOKIE"

	DefaultSIDCookie = "oauthgo_sid"

	ContentTypeHTML = "text/html; charset=utf-8"

	PathRoot         = "/"
	PathAuth         = "/auth/"
	PathCallback     = "/callback/"
	PathMe           = "/me"
	PathLogout       = "/logout"
	PathLogoutRevoke = "/logout-and-revoke"

	PromptSelectAccount = "select_account"

	HTMLRootHeader   = "<h3>oauthgo demo</h3><ul>"
	HTMLRootFooter   = "</ul><p><a href='/me'>/me</a></p>"
	HTMLSignedIn     = "<h3>Signed-in</h3><pre>%+v</pre>"
	HTMLServerSess   = "<h4>Server session</h4><pre>%+v</pre><p><a href='/logout'>Logout</a> | <a href='/logout-and-revoke'>Logout & Revoke</a></p>"
	HTMLLoggedOut    = "<p>Logged out. <a href='/'>Home</a></p>"
	HTMLLoggedOutRev = "<p>Logged out & revoke attempted. <a href='/'>Home</a></p>"

	ErrNotSignedIn = "not signed in"
)

// -----------------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------------

// SetupHTTPHandlers sets up the HTTP handlers for the OAuth manager.
func SetupHTTPHandlers(m *oauthgoprovidermanager.ProviderManager, cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) {
	http.HandleFunc(PathRoot, createRootHandler(m))
	http.HandleFunc(PathAuth, m.LoginHandler(func(r *http.Request) coreprovider.AuthOptions {
		return coreprovider.AuthOptions{
			RedirectURL: defaultRedirect(r),
			Prompt:      PromptSelectAccount,
		}
	}))
	http.HandleFunc(PathCallback, m.CallbackHandler(cookieMgr, sessionStore))
	http.HandleFunc(PathMe, createMeHandler(cookieMgr, sessionStore))
	http.HandleFunc(PathLogout, createLogoutHandler(cookieMgr, sessionStore))
	http.HandleFunc(PathLogoutRevoke, createLogoutAndInvokeHandler(m, cookieMgr, sessionStore))
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

// createRootHandler creates a handler for the root page.
func createRootHandler(m *oauthgoprovidermanager.ProviderManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ContentTypeHTML)
		s := HTMLRootHeader
		for name := range m.Providers {
			s += fmt.Sprintf("<li><a href='%s%s'>Login with %s</a></li>", PathAuth, name, cases.Title(language.English).String(name))
		}
		s += HTMLRootFooter
		_, err := w.Write([]byte(s))
		if err != nil {
			panic(err)
			return
		}
	}
}

// createMeHandler creates a handler for the /me page.
func createMeHandler(cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s, ok := cookieMgr.Parse(r); ok {
			w.Header().Set("Content-Type", ContentTypeHTML)
			_, err := w.Write([]byte(fmt.Sprintf(HTMLSignedIn, *s)))
			if err != nil {
				return
			}
			if sid, err := r.Cookie(env2.Get(EnvSIDCookie, DefaultSIDCookie)); err == nil {
				if sd, ok, _ := sessionStore.Get(r.Context(), sid.Value); ok {
					_, err := w.Write([]byte(fmt.Sprintf(HTMLServerSess, sd)))
					if err != nil {
						panic(err)
						return
					}
				}
			}
			return
		}
		http.Error(w, ErrNotSignedIn, http.StatusUnauthorized)
	}
}

// createLogoutHandler creates a handler for the /logout page.
func createLogoutHandler(cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sid, err := r.Cookie(env2.Get(EnvSIDCookie, DefaultSIDCookie)); err == nil {
			_ = sessionStore.Del(r.Context(), sid.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     env2.Get(EnvSIDCookie, DefaultSIDCookie),
			Value:    "",
			Path:     PathRoot,
			HttpOnly: true,
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
		})
		cookieMgr.Clear(w)
		w.Header().Set("Content-Type", ContentTypeHTML)
		_, err := w.Write([]byte(HTMLLoggedOut))
		if err != nil {
			panic(err)
			return
		}
	}
}

// createLogoutAndInvokeHandler creates a handler for the /logout-and-revoke page.
func createLogoutAndInvokeHandler(m *oauthgoprovidermanager.ProviderManager, cookieMgr *oauthgocookie.CookieSessionManager, sessionStore oauthgostore.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sid, err := r.Cookie(env2.Get(EnvSIDCookie, DefaultSIDCookie)); err == nil {
			if sd, ok, _ := sessionStore.Get(r.Context(), sid.Value); ok {
				if p, found := m.Providers[sd.Provider]; found && sd.AccessToken != "" {
					_ = p.Revoke(r.Context(), sd.AccessToken)
				}
				_ = sessionStore.Del(r.Context(), sid.Value)
			}
			http.SetCookie(w, &http.Cookie{
				Name:     env2.Get(EnvSIDCookie, DefaultSIDCookie),
				Value:    "",
				Path:     PathRoot,
				HttpOnly: true,
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
			})
		}
		cookieMgr.Clear(w)
		w.Header().Set("Content-Type", ContentTypeHTML)
		_, err := w.Write([]byte(HTMLLoggedOutRev))
		if err != nil {
			panic(err)
			return
		}
	}
}

// defaultRedirect returns the default redirect URL for the given request.
func defaultRedirect(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	prov := parts[len(parts)-1]
	return fmt.Sprintf("%s://%s%s%s", scheme, r.Host, PathCallback, prov)
}
