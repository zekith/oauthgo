package oauthgotypes

// Mode represents the authentication mode.
type Mode int

const (
	OAuth2Only Mode = iota
	OIDC
)

// OAuth2Options are the options for OAuth2.
type OAuth2Options struct {
	AuthURL          *string   // required
	TokenURL         *string   // required
	RevocationURL    *string   // optional, provide if the provider supports RFC7009 token revocation
	Scopes           *[]string // required
	PKCEAuthURL      *string   // optional, defaults to AuthURL
	PKCEPublicClient *bool     // optional, defaults to false (if true, client secret is not sent in token exchange)
	UsePKCE          *bool     // optional, defaults to true. Set false to disable PKCE (not recommended)
	ExtraAuth        *map[string]string
}

// OIDCOptions are the options for OIDC.
type OIDCOptions struct {
	Issuer                     *string   // required
	JWKSURL                    *string   // optional
	UserInfoURL                *string   // required
	Scopes                     *[]string // required
	DisableDiscovery           *bool     // optional, defaults to false. Set to true to skip OIDC discovery (not recommended)
	DisableIdTokenVerification *bool     // optional, defaults to false. Set to true to skip id_token verification (not recommended)
}

// OAuth2OIDCOptions are the options for the provider.
type OAuth2OIDCOptions struct {
	Name        *string        // optional
	Mode        *Mode          // optional
	OAuth2      *OAuth2Options // optional
	OIDC        *OIDCOptions   // optional
	UserInfoURL *string        //  used for providers which don't support OIDC but have a userinfo endpoint e.g. Github
}

// ProviderConfig is the config for the provider.
type ProviderConfig struct {
	ClientID          string
	ClientSecret      string
	OAuth2ODICOptions *OAuth2OIDCOptions
}
