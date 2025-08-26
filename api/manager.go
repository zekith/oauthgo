package oauthgo

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	oauthgocookie "github.com/zekith/oauthgo/core/cookie"
	authogodeps "github.com/zekith/oauthgo/core/deps"
	oauthgoauth2 "github.com/zekith/oauthgo/core/provider/oauth2"
	"github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgooidc "github.com/zekith/oauthgo/core/provider/oidc"
	oauthgostore "github.com/zekith/oauthgo/core/store"
	oauthgoutils "github.com/zekith/oauthgo/core/utils"
)

const (
	ContentTypeHTML  = "text/html; charset=utf-8"
	HTMLSignedIn     = "<h3>Signed-in</h3><pre>%+v</pre>"
	EnvSIDCookie     = "SID_COOKIE"
	HTMLServerSess   = "<h4>Server session</h4><pre>%+v</pre><p><a href='/logout'>Logout</a> | <a href='/logout-and-revoke'>Logout & Revoke</a></p>"
	DefaultSIDCookie = "oauthgo_sid"
	ErrNotSignedIn   = "not signed in"
	PathRoot         = "/"
	HTMLLoggedOutRev = "<p>Logged out <a href='/'>Home</a></p>"
)

// ProviderManager is the main entry point for the OIDC provider.
type ProviderManager struct {
	providers map[string]oauth2oidc.OAuthO2IDCProvider
}

// NewProviderManager creates a new ProviderManager.
func NewProviderManager() *ProviderManager {
	return &ProviderManager{
		providers: map[string]oauth2oidc.OAuthO2IDCProvider{},
	}
}

// Register registers a provider.
func (m *ProviderManager) Register(name string, provider oauth2oidc.OAuthO2IDCProvider) {
	fmt.Println("Registering provider: " + name)
	m.providers[name] = provider
}

// AuthURL returns the URL to redirect the user to for authentication.
func (m *ProviderManager) AuthURL(
	providerName string,
	r *http.Request,
	opts AuthURLOptions,
) (string, string, error) {

	provider, ok := m.providers[providerName]
	if !ok {
		return "", "", errors.New("provider not registered: " + providerName)
	}
	return provider.AuthURL(r.Context(), r, opts)
}

// Callback handles the callback after the user logs in.
func (m *ProviderManager) Callback(
	providerName string,
	w http.ResponseWriter,
	r *http.Request,
	opts CallbackOptions,
) (*CallbackResult, error) {
	provider, err := m.validateProvider(providerName)
	if err != nil {
		return nil, err
	}

	oAuth2Session, err := m.exchangeCodeForToken(r, provider)
	if err != nil {
		return nil, err
	}

	user, err := m.fetchUserInfo(r, provider, oAuth2Session)
	if err != nil {
		return nil, err
	}

	sid, err := m.handleSessionStorage(r, w, opts, oAuth2Session, user)
	if err != nil {
		return nil, err
	}

	if err := m.handleCookieStorage(w, opts, oAuth2Session, user); err != nil {
		return nil, err
	}

	return &CallbackResult{
		ProviderName: providerName,
		User:         user,
		Session:      oAuth2Session,
		SID:          sid,
	}, nil
}

// LoggedInUser returns the user if the user is logged in.
func (m *ProviderManager) LoggedInUser(
	w http.ResponseWriter,
	r *http.Request,
) {

	if s, ok := authogodeps.Get().SessionCookieManager.Parse(r); ok {
		w.Header().Set("Content-Type", ContentTypeHTML)
		_, err := w.Write([]byte(fmt.Sprintf(HTMLSignedIn, *s)))
		if err != nil {
			return
		}
		if sid, err := r.Cookie(oauthgoutils.Get(EnvSIDCookie, DefaultSIDCookie)); err == nil {
			if sd, ok, _ := authogodeps.Get().SessionStore.Get(r.Context(), sid.Value); ok {
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

// Revoke revokes the token.
func (m *ProviderManager) Revoke(
	providerName string,
	token string,
	r *http.Request,
) error {
	return m.providers[providerName].Revoke(r.Context(), token)
}

// Refresh refreshes the access token based on a refresh token.
func (m *ProviderManager) Refresh(
	providerName string,
	refreshToken string,
	r *http.Request,
) (*oauthgoauth2.OAuth2Session, error) {
	return m.providers[providerName].Refresh(r.Context(), refreshToken)
}

// Logout logs out the user.
func (m *ProviderManager) Logout(
	w http.ResponseWriter,
	r *http.Request,
) {
	if sid, err := r.Cookie(oauthgoutils.Get(EnvSIDCookie, DefaultSIDCookie)); err == nil {
		if sd, ok, _ := authogodeps.Get().SessionStore.Get(r.Context(), sid.Value); ok {
			if p, found := m.providers[sd.Provider]; found && sd.AccessToken != "" {
				// Revoke the access token
				_ = p.Revoke(r.Context(), sd.AccessToken)
			}
			_ = authogodeps.Get().SessionStore.Del(r.Context(), sid.Value)
		}
		// Clear SID cookie
		http.SetCookie(w, &http.Cookie{
			Name:     oauthgoutils.Get(EnvSIDCookie, DefaultSIDCookie),
			Value:    "",
			Path:     PathRoot,
			HttpOnly: true,
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
		})
	}
	// Clear session cookie
	authogodeps.Get().SessionCookieManager.Clear(w)
	w.Header().Set("Content-Type", ContentTypeHTML)
	_, err := w.Write([]byte(HTMLLoggedOutRev))
	if err != nil {
		panic(err)
		return
	}
}

// validateProvider validates the provider.
func (m *ProviderManager) validateProvider(providerName string) (oauth2oidc.OAuthO2IDCProvider, error) {
	provider, ok := m.providers[providerName]
	if !ok {
		return nil, errors.New("provider not registered: " + providerName)
	}
	return provider, nil
}

// exchangeCodeForToken exchanges the code for a token.
func (m *ProviderManager) exchangeCodeForToken(r *http.Request, provider oauth2oidc.OAuthO2IDCProvider) (*SessionData, error) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	return provider.Exchange(r.Context(), r, code, state)
}

// fetchUserInfo fetches the user info.
func (m *ProviderManager) fetchUserInfo(r *http.Request, provider oauth2oidc.OAuthO2IDCProvider, session *SessionData) (*oauthgooidc.User, error) {
	return provider.UserInfo(r.Context(), session.AccessToken, session.IDToken)
}

// handleSessionStorage handles the session storage.
func (m *ProviderManager) handleSessionStorage(r *http.Request, w http.ResponseWriter, opts CallbackOptions, session *SessionData, user *oauthgooidc.User) (string, error) {
	if !opts.StoreSession || authogodeps.Get().SessionStore == nil {
		return "", nil
	}

	sid := oauthgoutils.MustRandom(24)
	sessionData := oauthgostore.SessionData{
		Provider:     session.Provider,
		Subject:      user.Subject,
		Email:        user.Email,
		Name:         user.Name,
		AccessToken:  session.AccessToken,
		RefreshToken: session.RefreshToken,
		Expiry:       session.Expiry,
		CreatedAt:    time.Now(),
	}

	if err := authogodeps.Get().SessionStore.Put(r.Context(), sid, sessionData, 24*time.Hour); err != nil {
		return "", err
	}

	if opts.SetSIDCookie {
		m.setSIDCookie(w, sid)
	}

	return sid, nil
}

// setSIDCookie sets the SID cookie.
func (m *ProviderManager) setSIDCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     DefaultSIDCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// handleCookieStorage handles the cookie storage.
func (m *ProviderManager) handleCookieStorage(w http.ResponseWriter, opts CallbackOptions, session *SessionData, user *oauthgooidc.User) error {
	if !opts.SetLoginCookie || authogodeps.Get().SessionCookieManager == nil {
		return nil
	}

	cookieSession := oauthgocookie.SessionCookiePayload{
		Provider: session.Provider,
		Subject:  user.Subject,
		Email:    user.Email,
		Name:     user.Name,
		Expiry:   time.Now().Add(authogodeps.Get().SessionCookieManager.Expiry()),
	}

	return authogodeps.Get().SessionCookieManager.Set(w, cookieSession)
}
