package oauthgotypes

import (
	"encoding/json"
	"strings"
)

type BoolString bool

// UnmarshalJSON implements the json.Unmarshaler interface.
func (b *BoolString) UnmarshalJSON(data []byte) error {
	if b.isBooleanJSON(data) {
		return b.parseBooleanFromJSON(data)
	}

	return b.parseBooleanFromString(data)
}

// isBooleanJSON returns true if the data is a boolean value in JSON.
func (b *BoolString) isBooleanJSON(data []byte) bool {
	dataStr := string(data)
	return dataStr == "true" || dataStr == "false"
}

// parseBooleanFromJSON parses a boolean value from JSON.
func (b *BoolString) parseBooleanFromJSON(data []byte) error {
	var v bool
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*b = BoolString(v)
	return nil
}

// parseBooleanFromString parses a boolean value from a string.
func (b *BoolString) parseBooleanFromString(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		b.setBooleanValue(b.stringToBool(s))
		return nil
	}

	// Default to false if unrecognized
	b.setBooleanValue(false)
	return nil
}

// stringToBool converts a string to a boolean value.
func (b *BoolString) stringToBool(s string) bool {
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return false
	}
}

// setBooleanValue sets the boolean value.
func (b *BoolString) setBooleanValue(value bool) {
	*b = BoolString(value)
}
