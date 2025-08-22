package oauthgohelper

import (
	"fmt"
	"net/http"

	"github.com/AlekSi/pointer"
	oauth2core "github.com/zekith/oauthgo/core/oauth2"
	oidccore "github.com/zekith/oauthgo/core/oidc"
	coreprov "github.com/zekith/oauthgo/core/provider"
	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostate "github.com/zekith/oauthgo/core/state"
)

type baseProviderInput struct {
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

func BuildProviderFromDefaults(
	input *coreprov.ProviderInput,
	defaultOpts *coreprov.ProviderOptions,
) (coreprov.Provider, error) {

	opts := input.Options

	if opts == nil {
		// Set defaults so that we don't have to check for nil everywhere'
		opts = defaultOpts
	}

	name := resolveName(opts, func(o *coreprov.ProviderOptions) string { return pointer.GetString(o.Name) }, pointer.GetString(defaultOpts.Name))
	mode := pointer.Get(resolveMode(opts, func(o *coreprov.ProviderOptions) *coreprov.Mode { return o.Mode }, defaultOpts.Mode))

	baseInput := &baseProviderInput{
		stateCodec:      input.StateCodec,
		replayProtector: input.ReplayProtector,
		httpClient:      input.HttpClient,
		clientID:        input.ClientID,
		clientSecret:    input.ClientSecret,
		name:            name,
	}

	switch mode {
	case coreprov.OAuth2Only:
		scopes := pointer.Get(resolveScopes(opts.OAuth2, func(o *coreprov.OAuth2Options) *[]string { return o.Scopes }, defaultOpts.OAuth2.Scopes))
		authURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.AuthURL }, defaultOpts.OAuth2.AuthURL))
		tokenURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.TokenURL }, defaultOpts.OAuth2.TokenURL))
		revURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.RevocationURL }, defaultOpts.OAuth2.RevocationURL))
		usePKCE := pointer.GetBool(resolveUsePKCE(opts.OAuth2, func(o *coreprov.OAuth2Options) *bool { return o.UsePKCE }, defaultOpts.OAuth2.UsePKCE))

		baseInput.scopes = scopes
		baseInput.authURL = authURL
		baseInput.tokenURL = tokenURL
		baseInput.revokeTokenURL = revURL
		baseInput.usePKCE = usePKCE

		base := createBaseProvider(baseInput)
		return coreprov.NewAuthFacade(base, nil), nil

	case coreprov.OAuth2PKCE:
		scopes := pointer.Get(resolveScopes(opts.OAuth2, func(o *coreprov.OAuth2Options) *[]string { return o.Scopes }, defaultOpts.OAuth2.Scopes))

		pkceURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.PKCEAuthURL }, defaultOpts.OAuth2.PKCEAuthURL))
		tokenURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.TokenURL }, defaultOpts.OAuth2.TokenURL))
		revURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.RevocationURL }, defaultOpts.OAuth2.RevocationURL))
		usePKCE := pointer.GetBool(resolveUsePKCE(opts.OAuth2, func(o *coreprov.OAuth2Options) *bool { return o.UsePKCE }, defaultOpts.OAuth2.UsePKCE))

		// Public client? (omit client_secret)
		publicClient := defaultOpts.OAuth2.PKCEPublicClient

		if publicClient != nil && *publicClient {
			baseInput.clientSecret = ""
		}

		baseInput.scopes = scopes
		baseInput.authURL = pkceURL
		baseInput.tokenURL = tokenURL
		baseInput.revokeTokenURL = revURL
		baseInput.usePKCE = usePKCE

		base := createBaseProvider(baseInput)
		// PKCE usage itself is enforced at call-site via AuthOptions.UsePKCE = true
		return coreprov.NewAuthFacade(base, nil), nil

	case coreprov.OIDC:
		// Base OAuth2
		scopes := pointer.Get(resolveOIDCScopes(opts.OIDC, func(o *coreprov.OIDCOptions) *[]string { return o.Scopes }, defaultOpts.OIDC.Scopes))
		authURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.AuthURL }, defaultOpts.OAuth2.AuthURL))
		tokenURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.TokenURL }, defaultOpts.OAuth2.TokenURL))
		revURL := pointer.GetString(resolveURL(opts.OAuth2, func(o *coreprov.OAuth2Options) *string { return o.RevocationURL }, defaultOpts.OAuth2.RevocationURL))
		usePKCE := pointer.GetBool(resolveUsePKCE(opts.OAuth2, func(o *coreprov.OAuth2Options) *bool { return o.UsePKCE }, defaultOpts.OAuth2.UsePKCE))
		disableIdTokenVerification := pointer.GetBool(resolveDisableIdTokenVerification(opts.OIDC, func(o *coreprov.OIDCOptions) *bool { return o.DisableIdTokenVerification }, defaultOpts.OIDC.DisableIdTokenVerification))

		baseInput.scopes = scopes
		baseInput.authURL = authURL
		baseInput.tokenURL = tokenURL
		baseInput.revokeTokenURL = revURL
		baseInput.usePKCE = usePKCE
		baseInput.disableIdTokenVerification = disableIdTokenVerification

		base := createBaseProvider(baseInput)

		// OIDC decorator
		issuer := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *coreprov.OIDCOptions) *string { return o.Issuer }, defaultOpts.OIDC.Issuer))
		jwksURL := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *coreprov.OIDCOptions) *string { return o.JWKSURL }, defaultOpts.OIDC.JWKSURL))
		uiURL := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *coreprov.OIDCOptions) *string { return o.UserInfoURL }, defaultOpts.OIDC.UserInfoURL))
		disableDiscovery := pointer.GetBool(resolveDisableDiscovery(opts.OIDC, func(o *coreprov.OIDCOptions) *bool { return o.DisableDiscovery }, defaultOpts.OIDC.DisableDiscovery))

		dec, err := oidccore.NewOIDCDecorator(base, input.HttpClient, oidccore.OIDCConfig{
			Issuer:                     issuer,
			JWKSURL:                    jwksURL,
			UserInfoURL:                uiURL,
			DisableDiscovery:           disableDiscovery,
			ClientID:                   input.ClientID,
			DisableIdTokenVerification: baseInput.disableIdTokenVerification,
		})
		if err != nil {
			return nil, err
		}
		return coreprov.NewAuthFacade(base, dec), nil

	default:
		return nil, fmt.Errorf("unsupported mode")
	}
}

func createBaseProvider(
	input *baseProviderInput,
) oauth2core.AuthorisationProvider {
	return oauth2core.NewBaseOAuth2Provider(input.name, oauth2core.OAuth2Config{
		ClientID:      input.clientID,
		ClientSecret:  input.clientSecret,
		Scopes:        input.scopes,
		AuthURL:       input.authURL,
		TokenURL:      input.tokenURL,
		RevocationURL: input.revokeTokenURL,
		UsePKCE:       input.usePKCE,
	}, input.stateCodec, input.replayProtector, input.httpClient)
}

func resolveMode(opts *coreprov.ProviderOptions, getter func(*coreprov.ProviderOptions) *coreprov.Mode, defaultMode *coreprov.Mode) *coreprov.Mode {
	if opts != nil {
		if mode := getter(opts); mode != nil {
			return mode
		}
	}
	return defaultMode
}

func resolveDisableDiscovery(opts *coreprov.OIDCOptions, getter func(*coreprov.OIDCOptions) *bool, defaultDisableDiscovery *bool) *bool {
	if opts != nil {
		if disableDiscovery := getter(opts); disableDiscovery != nil {
			return disableDiscovery
		}
	}
	return defaultDisableDiscovery
}

func resolveUsePKCE(opts *coreprov.OAuth2Options, getter func(*coreprov.OAuth2Options) *bool, defaultUsePKCE *bool) *bool {
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

func resolveDisableIdTokenVerification(opts *coreprov.OIDCOptions, getter func(*coreprov.OIDCOptions) *bool, defaultDisableIdTokenVerification *bool) *bool {
	if opts != nil {
		if disableIdTokenVerification := getter(opts); disableIdTokenVerification != nil {
			return disableIdTokenVerification
		}
	}
	return defaultDisableIdTokenVerification
}

func resolveName(opts *coreprov.ProviderOptions, getter func(*coreprov.ProviderOptions) string, defaultName string) string {
	if opts != nil {
		if name := getter(opts); name != "" {
			return name
		}
	}
	return defaultName
}

func resolveURL(oauth2Opts *coreprov.OAuth2Options, getter func(*coreprov.OAuth2Options) *string, defaultURL *string) *string {
	if oauth2Opts != nil {
		if url := getter(oauth2Opts); url != nil {
			return url
		}
	}
	return defaultURL
}

func resolveOIDCURL(oidcOpts *coreprov.OIDCOptions, getter func(*coreprov.OIDCOptions) *string, defaultURL *string) *string {
	if oidcOpts != nil {
		if url := getter(oidcOpts); url != nil {
			return url
		}
	}
	return defaultURL
}

func resolveScopes(oauth2Opts *coreprov.OAuth2Options, getter func(options *coreprov.OAuth2Options) *[]string, defaultScopes *[]string) *[]string {
	if oauth2Opts != nil {
		if scopes := getter(oauth2Opts); scopes != nil {
			return scopes
		}
	}
	return defaultScopes
}

func resolveOIDCScopes(oidcOpts *coreprov.OIDCOptions, getter func(*coreprov.OIDCOptions) *[]string, defaultScopes *[]string) *[]string {
	if oidcOpts != nil {
		if scopes := getter(oidcOpts); scopes != nil {
			return scopes
		}
	}
	return defaultScopes
}
