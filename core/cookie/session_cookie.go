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

	signedPayload := m.signSessionData(b)
	cookie := m.createSessionCookie(signedPayload, s.Expiry)

	http.SetCookie(w, cookie)
	return nil
}

// signSessionData signs the session data and returns the base64-encoded payload.
func (m *CookieSessionManager) signSessionData(data []byte) string {
	h := hmac.New(sha256.New, m.Secret)
	h.Write(data)
	sig := h.Sum(nil)

	payload := append(data, sig...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

// createSessionCookie creates an HTTP cookie with the signed payload.
func (m *CookieSessionManager) createSessionCookie(value string, expiry time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     m.Name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiry,
		Domain:   m.Domain,
	}
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
	rawData, signature, ok := m.getCookieValue(r)
	if !ok {
		return nil, false
	}

	if !m.verifyCookieSignature(rawData, signature) {
		return nil, false
	}

	return m.parseSessionData(rawData)
}

// getCookieValue retrieves and decodes the cookie value, returning raw data and signature.
func (m *CookieSessionManager) getCookieValue(r *http.Request) ([]byte, []byte, bool) {
	c, err := r.Cookie(m.Name)
	if err != nil {
		return nil, nil, false
	}

	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(b) < sha256.Size {
		return nil, nil, false
	}

	raw := b[:len(b)-sha256.Size]
	sig := b[len(b)-sha256.Size:]
	return raw, sig, true
}

// verifyCookieSignature verifies the HMAC signature of the cookie data.
func (m *CookieSessionManager) verifyCookieSignature(rawData, signature []byte) bool {
	h := hmac.New(sha256.New, m.Secret)
	h.Write(rawData)
	return hmac.Equal(signature, h.Sum(nil))
}

// parseSessionData unmarshals the session data and validates expiry.
func (m *CookieSessionManager) parseSessionData(rawData []byte) (*CookieSession, bool) {
	var s CookieSession
	if err := json.Unmarshal(rawData, &s); err != nil {
		return nil, false
	}

	if time.Now().After(s.Expiry) {
		return nil, false
	}

	return &s, true
}
