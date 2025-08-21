package oauthgostate

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zekith/oauthgo/core/utils"
)

// StatePayload is the payload of a state token.
type StatePayload struct {
	// Provider is the name of the OAuth provider.
	Provider string `json:"provider"`
	// Nonce is a unique value to prevent replay attacks.
	Nonce string `json:"nonce"`
	// CSRF is a value to prevent CSRF attacks.
	CSRF string `json:"csrf"`
	// PKCE is the Proof Key for Code Exchange, used in OAuth 2.0 PKCE flows.
	PKCE *oauthgoutils.PKCE `json:"pkce,omitempty"`
	// Redirect is the URL to redirect the user to after authentication.
	Redirect string `json:"redirect"`
	// IssuedAt is the timestamp when the state was issued.
	IssuedAt int64 `json:"iat"`
	// Extras is a map of additional data that can be included in the state.
	// This can be used to pass custom parameters or data that the application needs.
	Extras map[string]string `json:"extras,omitempty"`
}

// StateCodec is a state token encoder/decoder.
type StateCodec struct {
	HMACSecret []byte
	TTL        time.Duration
}

// Encode encodes a state payload with HMAC signing and base64 encoding.
// The state payload must contain a provider, nonce, CSRF, and redirect URL.
// The PKCE field is optional and can be used for PKCE flows.
func (c *StateCodec) Encode(sp StatePayload) (string, error) {
	raw, err := json.Marshal(sp)
	if err != nil {
		return "", err
	}
	// sign the state
	m := hmac.New(sha256.New, c.HMACSecret)
	m.Write(raw)
	sig := m.Sum(nil)
	token := append(raw, sig...)
	// encode the state
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// Decode decodes a state payload from a base64 encoded string.
// It verifies the HMAC signature and checks if the state is expired based on the TTL.
// If the state is valid, it returns the decoded StatePayload.
// If the state is invalid or expired, it returns an error.
func (c *StateCodec) Decode(s string) (StatePayload, error) {
	// decode the state
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		fmt.Print("base64 decode error ", err)
		return StatePayload{}, err
	}
	// verify the state
	if len(b) < sha256.Size {
		fmt.Print("bad state length ", len(b))
		return StatePayload{}, errors.New("bad state")
	}
	raw, sig := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	m := hmac.New(sha256.New, c.HMACSecret)
	m.Write(raw)
	if !hmac.Equal(sig, m.Sum(nil)) {
		fmt.Print("bad state signature")
		return StatePayload{}, errors.New("bad state signature")
	}
	// unmarshal the state
	var sp StatePayload
	if err := json.Unmarshal(raw, &sp); err != nil {
		fmt.Print("json unmarshal error ", err)
		return StatePayload{}, err
	}
	// check if the state is expired
	if c.TTL > 0 && time.Since(time.Unix(sp.IssuedAt, 0)) > c.TTL {
		fmt.Print("state expired")
		return StatePayload{}, errors.New("state expired")
	}
	// return the state
	return sp, nil
}
