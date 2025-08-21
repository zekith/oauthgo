package oauthgolinkedin

import (
	"net/http"

	"github.com/AlekSi/pointer"
	coreoidc "github.com/zekith/oauthgo/core/oidc"
	"github.com/zekith/oauthgo/core/replay"
	"github.com/zekith/oauthgo/core/state"
)

// New returns an OIDC-based LinkedIn provider using discovery-less configuration.
func New(stateCodec *oauthgostate.StateCodec, rp oauthgoreplay.ReplayProtector, httpClient *http.Client, clientID, clientSecret string) (*coreoidc.OIDCProvider, error) {
	cfg := coreoidc.OIDCConfig{
		Issuer:           "https://www.linkedin.com/oauth",
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		DisableDiscovery: true,
		AuthURL:          "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:         "https://www.linkedin.com/oauth/v2/accessToken",
		UserInfoURL:      "https://api.linkedin.com/v2/userinfo",
		JWKSURL:          "https://www.linkedin.com/oauth/openid/jwks",
		RevocationURL:    "https://www.linkedin.com/oauth/v2/revoke",
		SupportsPKCE:     pointer.ToBool(false),
	}
	return coreoidc.NewOIDCProvider("linkedin", cfg, stateCodec, rp, httpClient)
}
