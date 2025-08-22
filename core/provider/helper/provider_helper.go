package oauthgohelper

import (
	"fmt"
	"net/http"

	"github.com/AlekSi/pointer"
	coreprov "github.com/zekith/oauthgo/core/provider"
	"github.com/zekith/oauthgo/core/provider/oauth2"
	oidccore "github.com/zekith/oauthgo/core/provider/oidc"
	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostate "github.com/zekith/oauthgo/core/state"
	"github.com/zekith/oauthgo/core/types"
)

// authProviderInput is the input parameters for the auth provider.
type authProviderInput struct {
	stateCodec      *oauthgostate.StateCodec
	replayProtector oauthgoreplay.ReplayProtector
	httpClient      *http.Client
	clientID        string
	clientSecret    string

	name                       string
	scopes                     []string
	authURL                    string
	tokenURL                   string
	revokeTokenURL             string
	usePKCE                    bool
	disableIdTokenVerification bool
}

// BuildProviderFromDefaults builds a new OAuth2 provider based on the input parameters.
func BuildProviderFromDefaults(
	input *oauthgotypes.ProviderInput,
	defaultOpts *oauthgotypes.ProviderOptions,
) (coreprov.Provider, error) {

	opts := input.Options
	if opts == nil {
		// set options to default to avoid nil pointer dereference
		opts = defaultOpts
	}

	// Build the base auth input
	baseAuthInput := buildBaseAuthInput(input, opts, defaultOpts)

	// Resolve the mode
	mode := pointer.Get(resolveMode(opts, func(o *oauthgotypes.ProviderOptions) *oauthgotypes.Mode { return o.Mode }, defaultOpts.Mode))

	switch mode {
	// OAuth2 only
	case oauthgotypes.OAuth2Only:
		return buildOAuth2Provider(baseAuthInput, opts, defaultOpts)
	// OAuth2 and OIDC
	case oauthgotypes.OIDC:
		return buildOIDCProvider(baseAuthInput, opts, defaultOpts)

	default:
		return nil, fmt.Errorf("unsupported mode")
	}
}

// buildBaseAuthInput builds the base auth input.
func buildBaseAuthInput(
	input *oauthgotypes.ProviderInput,
	opts *oauthgotypes.ProviderOptions,
	defaultOpts *oauthgotypes.ProviderOptions,
) *authProviderInput {

	name := resolveName(opts, func(o *oauthgotypes.ProviderOptions) string { return pointer.GetString(o.Name) }, pointer.GetString(defaultOpts.Name))
	authURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *string { return o.AuthURL }, defaultOpts.OAuth2.AuthURL))
	tokenURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *string { return o.TokenURL }, defaultOpts.OAuth2.TokenURL))
	revURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *string { return o.RevocationURL }, defaultOpts.OAuth2.RevocationURL))
	usePKCE := pointer.GetBool(resolveUsePKCE(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *bool { return o.UsePKCE }, defaultOpts.OAuth2.UsePKCE))

	return &authProviderInput{
		stateCodec:      input.StateCodec,
		replayProtector: input.ReplayProtector,
		httpClient:      input.HttpClient,
		clientID:        input.ClientID,
		clientSecret:    input.ClientSecret,
		name:            name,
		authURL:         authURL,
		tokenURL:        tokenURL,
		revokeTokenURL:  revURL,
		usePKCE:         usePKCE,
	}
}

// buildOAuth2Provider builds a new OAuth2 provider based on the input parameters.
func buildOAuth2Provider(
	authInput *authProviderInput,
	opts *oauthgotypes.ProviderOptions,
	defaultOpts *oauthgotypes.ProviderOptions,
) (coreprov.Provider, error) {
	authScopes := pointer.Get(resolveScopes(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *[]string { return o.Scopes }, defaultOpts.OAuth2.Scopes))
	authInput.scopes = authScopes

	auth := createAuthProvider(authInput)

	return coreprov.NewAuthFacade(auth, nil), nil
}

// buildOIDCProvider builds a new OIDC provider based on the input parameters.
func buildOIDCProvider(
	authInput *authProviderInput,
	opts *oauthgotypes.ProviderOptions,
	defaultOpts *oauthgotypes.ProviderOptions,
) (coreprov.Provider, error) {

	oidcScopes := pointer.Get(resolveOIDCScopes(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *[]string { return o.Scopes }, defaultOpts.OIDC.Scopes))
	disableIdTokenVerification := pointer.GetBool(resolveDisableIdTokenVerification(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *bool { return o.DisableIdTokenVerification }, defaultOpts.OIDC.DisableIdTokenVerification))

	authInput.scopes = oidcScopes
	authInput.disableIdTokenVerification = disableIdTokenVerification

	auth := createAuthProvider(authInput)
	oidcDecorator, err := createOIDCDecorator(authInput, auth, opts, defaultOpts)
	if err != nil {
		return nil, err
	}

	return coreprov.NewAuthFacade(auth, oidcDecorator), nil
}

// createOIDCDecorator creates a new OIDC decorator based on the input parameters.
func createOIDCDecorator(input *authProviderInput,
	auth oauthgoauth2.AuthorisationProvider,
	opts *oauthgotypes.ProviderOptions,
	defaultOpts *oauthgotypes.ProviderOptions) (*oidccore.OIDCDecorator, error) {

	// OIDC decorator
	issuer := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *string { return o.Issuer }, defaultOpts.OIDC.Issuer))
	jwksURL := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *string { return o.JWKSURL }, defaultOpts.OIDC.JWKSURL))
	uiURL := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *string { return o.UserInfoURL }, defaultOpts.OIDC.UserInfoURL))
	disableDiscovery := pointer.GetBool(resolveDisableDiscovery(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *bool { return o.DisableDiscovery }, defaultOpts.OIDC.DisableDiscovery))

	return oidccore.NewOIDCDecorator(auth, input.httpClient, oidccore.OIDCConfig{
		Issuer:                     issuer,
		JWKSURL:                    jwksURL,
		UserInfoURL:                uiURL,
		DisableDiscovery:           disableDiscovery,
		ClientID:                   input.clientID,
		DisableIdTokenVerification: input.disableIdTokenVerification,
	})
}

// createAuthProvider creates a new OAuth2 authorisation provider based on the input parameters.
func createAuthProvider(
	input *authProviderInput,
) oauthgoauth2.AuthorisationProvider {
	return oauthgoauth2.NewBaseOAuth2Provider(input.name, oauthgoauth2.OAuth2Config{
		ClientID:      input.clientID,
		ClientSecret:  input.clientSecret,
		Scopes:        input.scopes,
		AuthURL:       input.authURL,
		TokenURL:      input.tokenURL,
		RevocationURL: input.revokeTokenURL,
		UsePKCE:       input.usePKCE,
	}, input.stateCodec, input.replayProtector, input.httpClient)
}

// resolveMode resolves the mode.
func resolveMode(opts *oauthgotypes.ProviderOptions, getter func(*oauthgotypes.ProviderOptions) *oauthgotypes.Mode, defaultMode *oauthgotypes.Mode) *oauthgotypes.Mode {
	if opts != nil {
		if mode := getter(opts); mode != nil {
			return mode
		}
	}
	return defaultMode
}

// resolveDisableDiscovery resolves the disable discovery flag.
func resolveDisableDiscovery(opts *oauthgotypes.OIDCOptions, getter func(*oauthgotypes.OIDCOptions) *bool, defaultDisableDiscovery *bool) *bool {
	if opts != nil {
		if disableDiscovery := getter(opts); disableDiscovery != nil {
			return disableDiscovery
		}
	}
	return defaultDisableDiscovery
}

// resolveUsePKCE resolves the use PKCE flag.
func resolveUsePKCE(opts *oauthgotypes.OAuth2Options, getter func(*oauthgotypes.OAuth2Options) *bool, defaultUsePKCE *bool) *bool {
	if opts != nil {
		if usePKCE := getter(opts); usePKCE != nil {
			return usePKCE
		}
	}
	if defaultUsePKCE == nil {
		// Default to true if not set
		return pointer.ToBool(true)
	}
	return defaultUsePKCE
}

// resolveDisableIdTokenVerification resolves the disable id token verification flag.
func resolveDisableIdTokenVerification(opts *oauthgotypes.OIDCOptions, getter func(*oauthgotypes.OIDCOptions) *bool, defaultDisableIdTokenVerification *bool) *bool {
	if opts != nil {
		if disableIdTokenVerification := getter(opts); disableIdTokenVerification != nil {
			return disableIdTokenVerification
		}
	}
	return defaultDisableIdTokenVerification
}

// resolveName resolves the name.
func resolveName(opts *oauthgotypes.ProviderOptions, getter func(*oauthgotypes.ProviderOptions) string, defaultName string) string {
	if opts != nil {
		if name := getter(opts); name != "" {
			return name
		}
	}
	return defaultName
}

// resolveURL resolves the URL.
func resolveURL(oauth2Opts *oauthgotypes.OAuth2Options, getter func(*oauthgotypes.OAuth2Options) *string, defaultURL *string) *string {
	if oauth2Opts != nil {
		if url := getter(oauth2Opts); url != nil {
			return url
		}
	}
	return defaultURL
}

// resolveOIDCURL resolves the OIDC URL.
func resolveOIDCURL(oidcOpts *oauthgotypes.OIDCOptions, getter func(*oauthgotypes.OIDCOptions) *string, defaultURL *string) *string {
	if oidcOpts != nil {
		if url := getter(oidcOpts); url != nil {
			return url
		}
	}
	return defaultURL
}

// resolveScopes resolves the scopes.
func resolveScopes(oauth2Opts *oauthgotypes.OAuth2Options, getter func(options *oauthgotypes.OAuth2Options) *[]string, defaultScopes *[]string) *[]string {
	if oauth2Opts != nil {
		if scopes := getter(oauth2Opts); scopes != nil {
			return scopes
		}
	}
	return defaultScopes
}

// resolveOIDCScopes resolves the OIDC scopes.
func resolveOIDCScopes(oidcOpts *oauthgotypes.OIDCOptions, getter func(*oauthgotypes.OIDCOptions) *[]string, defaultScopes *[]string) *[]string {
	if oidcOpts != nil {
		if scopes := getter(oidcOpts); scopes != nil {
			return scopes
		}
	}
	return defaultScopes
}
