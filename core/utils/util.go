package oauthgoutils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	ContentTypeJSON = "application/json; charset=utf-8"
)

// RandomStringURLSafe returns a URL-safe base64 string (no padding).
func RandomStringURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MustRandom panics on error; for places where we already handle outer errors.
func MustRandom(n int) string {
	s, err := RandomStringURLSafe(n)
	if err != nil {
		panic(err)
	}
	return s
}

// ApiError represents an error response.
type ApiError struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an error response as JSON.
func WriteError(w http.ResponseWriter, status int, msg string, err error) {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	WriteJSON(w, status, map[string]any{
		"error": ApiError{
			Message: msg,
			Detail:  detail,
		},
	})
}

// FirstNonEmpty returns the first non-empty string from the provided values.
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// StringValue converts any to string.
func StringValue(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(v)
	}
}

// Int64Value converts common numeric JSON forms to int64.
func Int64Value(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case float32:
		return int64(t), true
	case float64:
		return int64(t), true
	case json.Number:
		i, err := t.Int64()
		return i, err == nil
	case string:
		n := json.Number(t)
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}
