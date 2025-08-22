package oauthgotypes

import (
	"encoding/json"
	"strings"
)

// Locale is a custom type for handling OIDC locale claims.
type Locale struct {
	Value string
}

// localeObject represents the structure for locale JSON objects
type localeObject struct {
	Language string `json:"language"`
	Country  string `json:"country"`
}

func (l *Locale) UnmarshalJSON(b []byte) error {
	// Case 1: plain string, e.g. "en_US" or "en-US"
	if err := l.tryUnmarshalString(b); err == nil {
		return nil
	}

	// Case 2: object, e.g. {"language":"en","country":"US"}
	if err := l.tryUnmarshalObject(b); err == nil {
		return nil
	}

	// Unknown shape → leave empty
	l.Value = ""

	return nil
}

// tryUnmarshalString attempts to unmarshal the JSON as a plain string
func (l *Locale) tryUnmarshalString(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	l.Value = s
	return nil
}

// tryUnmarshalObject attempts to unmarshal the JSON as a locale object
func (l *Locale) tryUnmarshalObject(b []byte) error {
	var obj localeObject
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	l.Value = formatLocaleValue(obj)
	return nil
}

// formatLocaleValue formats a locale object into a string representation
func formatLocaleValue(obj localeObject) string {
	switch {
	case obj.Language != "" && obj.Country != "":
		return strings.ToLower(obj.Language) + "-" + strings.ToUpper(obj.Country)
	case obj.Language != "":
		return strings.ToLower(obj.Language)
	case obj.Country != "":
		return strings.ToUpper(obj.Country)
	default:
		return ""
	}
}
