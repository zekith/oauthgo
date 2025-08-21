package oauthgotypes

import (
	"encoding/json"
	"strings"
)

// Locale is a custom type for handling OIDC locale claims.
type Locale struct {
	Value string
}

func (l *Locale) UnmarshalJSON(b []byte) error {
	// Case 1: plain string, e.g. "en_US" or "en-US"
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		l.Value = s
		return nil
	}

	// Case 2: object, e.g. {"language":"en","country":"US"}
	var obj struct {
		Language string `json:"language"`
		Country  string `json:"country"`
	}
	if err := json.Unmarshal(b, &obj); err == nil {
		switch {
		case obj.Language != "" && obj.Country != "":
			l.Value = strings.ToLower(obj.Language) + "-" + strings.ToUpper(obj.Country)
		case obj.Language != "":
			l.Value = strings.ToLower(obj.Language)
		case obj.Country != "":
			l.Value = strings.ToUpper(obj.Country)
		default:
			l.Value = ""
		}
		return nil
	}

	// Unknown shape → leave empty
	l.Value = ""
	return nil
}
