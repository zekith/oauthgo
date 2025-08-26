package oauthgo

import (
	"encoding/json"
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
	ContentTypeJSON  = "application/json; charset=utf-8"
	EnvSIDCookie     = "SID_COOKIE"
	DefaultSIDCookie = "oauthgo_sid"
	ErrNotSignedIn   = "not signed in"
	PathRoot         = "/"
)

// ProviderManager is the main entry point for the OIDC/OAuth2 provider.
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

// LoggedInUser writes JSON information about the logged-in user (cookie + optional server session).
func (m *ProviderManager) LoggedInUser(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Content-Type", ContentTypeJSON)

	if s, ok := authogodeps.Get().SessionCookieManager.Parse(r); ok {
		resp := map[string]any{
			"status":          "signed_in",
			"cookie_session":  s,
			"server_session":  nil,
			"sid_cookie_name": oauthgoutils.Get(EnvSIDCookie, DefaultSIDCookie),
		}
		if sid, err := r.Cookie(oauthgoutils.Get(EnvSIDCookie, DefaultSIDCookie)); err == nil {
			if sd, ok, _ := authogodeps.Get().SessionStore.Get(r.Context(), sid.Value); ok {
				resp["server_session"] = sd
				resp["sid"] = sid.Value
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	writeError(w, http.StatusUnauthorized, ErrNotSignedIn, nil)
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

// Logout logs out the user (revoke if possible, clear server and browser sessions).
// Returns JSON by default; if a redirect target is provided via query (?redirect_uri=/ or ?rd=/),
// performs a 302 redirect instead.
func (m *ProviderManager) Logout(
	w http.ResponseWriter,
	r *http.Request,
) {
	redirectTarget := firstNonEmpty(r.URL.Query().Get("redirect_uri"), r.URL.Query().Get("rd"))

	resp := map[string]any{
		"status":          "logged_out",
		"revoked":         false,
		"server_session":  "cleared",
		"browser_cookies": "cleared",
	}

	if sid, err := r.Cookie(oauthgoutils.Get(EnvSIDCookie, DefaultSIDCookie)); err == nil {
		if sd, ok, _ := authogodeps.Get().SessionStore.Get(r.Context(), sid.Value); ok {
			if p, found := m.providers[sd.Provider]; found && sd.AccessToken != "" {
				if err := p.Revoke(r.Context(), sd.AccessToken); err == nil {
					resp["revoked"] = true
				}
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

	if redirectTarget != "" {
		http.Redirect(w, r, redirectTarget, http.StatusFound)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// ---------------------- internals ----------------------

func (m *ProviderManager) validateProvider(providerName string) (oauth2oidc.OAuthO2IDCProvider, error) {
	provider, ok := m.providers[providerName]
	if !ok {
		return nil, errors.New("provider not registered: " + providerName)
	}
	return provider, nil
}

func (m *ProviderManager) exchangeCodeForToken(r *http.Request, provider oauth2oidc.OAuthO2IDCProvider) (*SessionData, error) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	return provider.Exchange(r.Context(), r, code, state)
}

func (m *ProviderManager) fetchUserInfo(r *http.Request, provider oauth2oidc.OAuthO2IDCProvider, session *SessionData) (*oauthgooidc.User, error) {
	return provider.UserInfo(r.Context(), session.AccessToken, session.IDToken)
}

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

func (m *ProviderManager) setSIDCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthgoutils.Get(EnvSIDCookie, DefaultSIDCookie),
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

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

// ---------------------- JSON helpers ----------------------

type apiError struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string, err error) {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	writeJSON(w, status, map[string]any{
		"error": apiError{
			Message: msg,
			Detail:  detail,
		},
	})
}

// Utility: prefer the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
