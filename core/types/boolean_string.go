package oauthgotypes

import (
	"encoding/json"
	"strings"
)

type BoolString bool

func (b *BoolString) UnmarshalJSON(data []byte) error {
	// Handle JSON boolean
	if string(data) == "true" || string(data) == "false" {
		var v bool
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
		*b = BoolString(v)
		return nil
	}

	// Handle JSON string
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		switch strings.ToLower(s) {
		case "true", "1", "yes":
			*b = BoolString(true)
			return nil
		case "false", "0", "no":
			*b = BoolString(false)
			return nil
		}
	}

	// Default to false if unrecognized
	*b = BoolString(false)
	return nil
}
