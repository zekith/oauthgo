package oauthgomicrosoft

import (
	"fmt"
	"net/http"

	"github.com/zekith/oauthgo/core/oidc"
	"github.com/zekith/oauthgo/core/replay"
	"github.com/zekith/oauthgo/core/state"
)

// New returns an OIDC provider for Microsoft.
func New(state *oauthgostate.StateCodec, replay oauthgoreplay.ReplayProtector, httpClient *http.Client, tenant, clientID, clientSecret string) (*oauthgooidc.OIDCProvider, error) {
	// tenant can be "common", "organizations", or a directory (tenant) ID
	issuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)
	return oauthgooidc.NewOIDCProvider("microsoft", oauthgooidc.OIDCConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"offline_access"},
	}, state, replay, httpClient)
}
