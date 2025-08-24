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

const (
	minStateLength   = sha256.Size
	EnvStateHMAC     = "STATE_HMAC"
	StateCodecTTL    = 2 * time.Minute
	DefaultStateHMAC = "91df202ecc9b45b8b0209e60891098b5"
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

func GetStateCodec() *StateCodec {
	secret := oauthgoutils.Get(EnvStateHMAC, DefaultStateHMAC)
	return &StateCodec{HMACSecret: []byte(secret), TTL: StateCodecTTL}
}

// Encode encodes a state payload with HMAC signing and base64 encoding.
func (c *StateCodec) Encode(sp StatePayload) (string, error) {
	// marshal the payload
	raw, err := json.Marshal(sp)
	if err != nil {
		return "", err
	}

	// sign the payload
	token := c.signPayload(raw)

	// encode the token
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// Decode decodes a state payload from a base64 encoded string.
func (c *StateCodec) Decode(s string) (StatePayload, error) {
	// decode the token
	b, err := c.decodeBase64(s)
	if err != nil {
		return StatePayload{}, err
	}

	// verify the signature
	raw, err := c.verifySignature(b)
	if err != nil {
		return StatePayload{}, err
	}

	// unmarshal the payload
	sp, err := c.unmarshalPayload(raw)
	if err != nil {
		return StatePayload{}, err
	}

	// check if the state is expired
	if err := c.checkExpiration(sp); err != nil {
		return StatePayload{}, err
	}

	return sp, nil
}

// signPayload signs the raw payload with HMAC and appends the signature.
func (c *StateCodec) signPayload(raw []byte) []byte {
	m := hmac.New(sha256.New, c.HMACSecret)
	m.Write(raw)
	sig := m.Sum(nil)
	return append(raw, sig...)
}

// decodeBase64 decodes a base64 encoded string.
func (c *StateCodec) decodeBase64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode error: %w", err)
	}
	return b, nil
}

// verifySignature verifies the HMAC signature of the state.
func (c *StateCodec) verifySignature(b []byte) ([]byte, error) {
	if len(b) < minStateLength {
		return nil, fmt.Errorf("invalid state length %d, minimum required %d", len(b), minStateLength)
	}

	raw, sig := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	m := hmac.New(sha256.New, c.HMACSecret)
	m.Write(raw)

	if !hmac.Equal(sig, m.Sum(nil)) {
		return nil, errors.New("invalid state signature")
	}

	return raw, nil
}

// unmarshalPayload unmarshal the state payload.
func (c *StateCodec) unmarshalPayload(raw []byte) (StatePayload, error) {
	var sp StatePayload
	if err := json.Unmarshal(raw, &sp); err != nil {
		return StatePayload{}, fmt.Errorf("json unmarshal error: %w", err)
	}
	return sp, nil
}

// checkExpiration checks if the state is expired.
func (c *StateCodec) checkExpiration(sp StatePayload) error {
	if c.TTL > 0 && time.Since(time.Unix(sp.IssuedAt, 0)) > c.TTL {
		return errors.New("state expired")
	}
	return nil
}
