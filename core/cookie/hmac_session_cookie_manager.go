package oauthgocookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

const (
	// signatureSize represents the size of HMAC-SHA256 signature in bytes
	signatureSize = sha256.Size
)

// HMACSessionCookieManager is a session cookie manager that uses HMAC to sign the cookie data.
type HMACSessionCookieManager struct {
	// Name is the name of the cookie
	Name string
	// Secret is the secret used to sign the cookie data
	Secret []byte
	// TTL is the time-to-live of the cookie
	TTL time.Duration
	// Secure indicates whether the cookie should be secure
	Secure bool
	// Domain is the domain of the cookie
	Domain string
	// HttpOnly indicates whether the cookie should be HTTP-only
	HttpOnly bool
	// CookiePath is the path of the cookie
	CookiePath string
	// SameSite indicates whether the cookie should be same-site
	SameSite http.SameSite
}

// GetDefaultHMACCookieSessionManager returns the default HMACSessionCookieManager.
// You can override the default values by passing in a custom CookieSessionManager.
func GetDefaultHMACCookieSessionManager() SessionCookieManager {
	return &HMACSessionCookieManager{
		Name:       "oauth_session",
		Secret:     make([]byte, 0),
		TTL:        time.Hour * 24 * 30,
		Secure:     true,
		Domain:     "",
		HttpOnly:   true,
		CookiePath: "/",
		SameSite:   http.SameSiteLaxMode,
	}
}

// Set sets a session in a cookie.
func (m *HMACSessionCookieManager) Set(w http.ResponseWriter, s SessionCookiePayload) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	signedPayload := m.signSessionData(b)
	cookie := m.createSessionCookie(signedPayload, s.Expiry)
	http.SetCookie(w, cookie)
	return nil
}

// Clear clears a session cookie.
func (m *HMACSessionCookieManager) Clear(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     m.Name,
		Value:    "",
		Path:     m.CookiePath,
		HttpOnly: m.HttpOnly,
		Secure:   m.Secure,
		SameSite: m.SameSite,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1, // Negative MaxAge deletes the cookie
		Domain:   m.Domain,
	}
	http.SetCookie(w, cookie)
}

// Parse parses a session cookie.
func (m *HMACSessionCookieManager) Parse(r *http.Request) (*SessionCookiePayload, bool) {
	rawData, signature, ok := m.getCookieValue(r)
	if !ok {
		return nil, false
	}
	if !m.verifyCookieSignature(rawData, signature) {
		return nil, false
	}
	return m.parseSessionData(rawData)
}

// signSessionData signs the session data and returns the base64-encoded payload.
func (m *HMACSessionCookieManager) signSessionData(data []byte) string {
	h := hmac.New(sha256.New, m.Secret)
	h.Write(data)
	sig := h.Sum(nil)
	payload := append(data, sig...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

// createSessionCookie creates an HTTP cookie with the signed payload.
func (m *HMACSessionCookieManager) createSessionCookie(value string, expiry time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     m.Name,
		Value:    value,
		Path:     m.CookiePath,
		HttpOnly: m.HttpOnly,
		Secure:   m.Secure,
		SameSite: m.SameSite,
		Expires:  expiry,
		Domain:   m.Domain,
	}
}

// getCookieValue retrieves and decodes the cookie value, returning raw data and signature.
func (m *HMACSessionCookieManager) getCookieValue(r *http.Request) ([]byte, []byte, bool) {
	c, err := r.Cookie(m.Name)
	if err != nil {
		return nil, nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(b) < signatureSize {
		return nil, nil, false
	}
	raw := b[:len(b)-signatureSize]
	sig := b[len(b)-signatureSize:]
	return raw, sig, true
}

// verifyCookieSignature verifies the HMAC signature of the cookie data.
func (m *HMACSessionCookieManager) verifyCookieSignature(rawData, signature []byte) bool {
	h := hmac.New(sha256.New, m.Secret)
	h.Write(rawData)
	return hmac.Equal(signature, h.Sum(nil))
}

// parseSessionData unmarshal the session data and validates expiry.
func (m *HMACSessionCookieManager) parseSessionData(rawData []byte) (*SessionCookiePayload, bool) {
	var s SessionCookiePayload
	if err := json.Unmarshal(rawData, &s); err != nil {
		return nil, false
	}
	if time.Now().After(s.Expiry) {
		return nil, false
	}
	return &s, true
}

func (m *HMACSessionCookieManager) Expiry() time.Duration {
	return m.TTL
}
