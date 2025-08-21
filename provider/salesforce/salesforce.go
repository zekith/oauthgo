package oauthgosalesforce

import (
	"net/http"

	"github.com/zekith/oauthgo/core/oidc"
	"github.com/zekith/oauthgo/core/replay"
	"github.com/zekith/oauthgo/core/state"
)

// New returns an OIDC provider for Salesforce.
func New(state *oauthgostate.StateCodec, replay oauthgoreplay.ReplayProtector, httpClient *http.Client, issuer, clientID, clientSecret string) (*oauthgooidc.OIDCProvider, error) {
	// the issuer can be https://login.salesforce.com or your MyDomain issuer.
	return oauthgooidc.NewOIDCProvider("salesforce", oauthgooidc.OIDCConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"offline_access"},
	}, state, replay, httpClient)
}
