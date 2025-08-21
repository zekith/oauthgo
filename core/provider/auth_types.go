package oauthgoprovider

import (
	"net/http"

	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostate "github.com/zekith/oauthgo/core/state"
)

type Mode int

const (
	OAuth2Only Mode = iota
	OIDC
	OAuth2PKCE
)

type OAuth2Options struct {
	AuthURL          *string   // optional
	TokenURL         *string   // optional
	RevocationURL    *string   // optional
	Scopes           *[]string // optional (nil=inherit; &[]{}=override to empty)
	PKCEAuthURL      *string   // optional (some providers have a distinct PKCE auth endpoint)
	PKCEPublicClient *bool     // optional (nil=inherit; true/false explicit)
	UsePKCE          *bool
}
type OIDCOptions struct {
	Issuer           *string   // optional
	JWKSURL          *string   // optional
	UserInfoURL      *string   // optional
	Scopes           *[]string // optional
	DisableDiscovery *bool     // optional
}

type ProviderOptions struct {
	Name   *string        // optional
	Mode   *Mode          // optional
	OAuth2 *OAuth2Options // optional
	OIDC   *OIDCOptions   // optional
}

type ProviderInput struct {
	StateCodec      *oauthgostate.StateCodec
	ReplayProtector oauthgoreplay.ReplayProtector
	HttpClient      *http.Client
	ClientID        string
	ClientSecret    string
	Options         *ProviderOptions
}
