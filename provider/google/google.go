package oauthgogoogle

import (
	"net/http"

	"github.com/zekith/oauthgo/core/oidc"
	"github.com/zekith/oauthgo/core/replay"
	"github.com/zekith/oauthgo/core/state"
)

// New returns an OIDC provider for Google.
func New(state *oauthgostate.StateCodec, replay oauthgoreplay.ReplayProtector, httpClient *http.Client, clientID, clientSecret string) (*oauthgooidc.OIDCProvider, error) {
	return oauthgooidc.NewOIDCProvider("google", oauthgooidc.OIDCConfig{
		Issuer:       "https://accounts.google.com",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{},
	}, state, replay, httpClient)
}
