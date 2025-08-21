package oauthgocookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

// CookieSession is a session stored in a cookie.
type CookieSession struct {
	Provider string    `json:"provider"`
	Subject  string    `json:"sub"`
	Email    string    `json:"email"`
	Name     string    `json:"name"`
	Expiry   time.Time `json:"exp"`
}

// CookieSessionManager manages sessions stored in cookies.
type CookieSessionManager struct {
	Name   string
	Secret []byte
	TTL    time.Duration
	Secure bool
	Domain string
}

// Set sets a session in a cookie.
func (m *CookieSessionManager) Set(w http.ResponseWriter, s CookieSession) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	// sign the cookie
	h := hmac.New(sha256.New, m.Secret)
	h.Write(b)
	sig := h.Sum(nil)
	// create the cookie payload
	payload := append(b, sig...)
	// encode the cookie payload
	val := base64.RawURLEncoding.EncodeToString(payload)
	// Create the cookie
	cookie := &http.Cookie{
		Name:     m.Name,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  s.Expiry,
		Domain:   m.Domain,
	}
	// Set the cookie
	http.SetCookie(w, cookie)
	return nil
}

// Clear clears a session cookie.
func (m *CookieSessionManager) Clear(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     m.Name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1, // Negative MaxAge deletes the cookie
		Domain:   m.Domain,
	}
	http.SetCookie(w, cookie)
}

// Parse parses a session cookie.
func (m *CookieSessionManager) Parse(r *http.Request) (*CookieSession, bool) {
	// get the cookie
	c, err := r.Cookie(m.Name)
	if err != nil {
		return nil, false
	}
	// decode the cookie
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(b) < sha256.Size {
		return nil, false
	}
	// verify the cookie
	raw, sig := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	h := hmac.New(sha256.New, m.Secret)
	h.Write(raw)
	if !hmac.Equal(sig, h.Sum(nil)) {
		return nil, false
	}
	// unmarshal the cookie
	var s CookieSession
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	// check the expiry
	if time.Now().After(s.Expiry) {
		return nil, false
	}
	// return the session
	return &s, true
}
