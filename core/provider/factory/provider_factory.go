package oauthgofactory

import (
	"fmt"

	"github.com/AlekSi/pointer"
	oauthgoauth2 "github.com/zekith/oauthgo/core/provider/oauth2"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oidccore "github.com/zekith/oauthgo/core/provider/oidc"
	"github.com/zekith/oauthgo/core/types"
)

// oAuth2OIDCProviderConfig contains required fields to configure an OAuth2 or OIDC provider.
type oAuth2OIDCProviderConfig struct {
	clientID                string
	clientSecret            string
	name                    string
	scopes                  []string
	authURL                 string
	tokenURL                string
	revokeTokenURL          string
	usePKCE                 bool
	skipIDTokenVerification bool
	extraAuth               map[string]string
}

// NewOAuth2OIDCProvider constructs a provider (OAuth2 or OIDC) based on provider config + defaults.
func NewOAuth2OIDCProvider(
	providerConfig *oauthgotypes.ProviderConfig,
	defaultOpts *oauthgotypes.OAuth2OIDCOptions,
) (coreprov.OAuthO2IDCProvider, error) {

	opts := providerConfig.OAuth2ODICOptions
	if opts == nil {
		opts = defaultOpts
	}

	config := newOAuth2OIDCProviderConfig(providerConfig, opts, defaultOpts)
	mode := pointer.Get(resolveMode(opts, func(o *oauthgotypes.OAuth2OIDCOptions) *oauthgotypes.Mode { return o.Mode }, defaultOpts.Mode))

	switch mode {
	case oauthgotypes.OAuth2Only:
		return buildOAuth2Provider(config, opts, defaultOpts)
	case oauthgotypes.OIDC:
		return buildOIDCProvider(config, opts, defaultOpts)
	default:
		return nil, fmt.Errorf("unsupported mode")
	}
}

func newOAuth2OIDCProviderConfig(
	providerConfig *oauthgotypes.ProviderConfig,
	opts *oauthgotypes.OAuth2OIDCOptions,
	defaultOpts *oauthgotypes.OAuth2OIDCOptions,
) *oAuth2OIDCProviderConfig {

	return &oAuth2OIDCProviderConfig{
		clientID:       providerConfig.ClientID,
		clientSecret:   providerConfig.ClientSecret,
		name:           resolveName(opts, func(o *oauthgotypes.OAuth2OIDCOptions) string { return pointer.GetString(o.Name) }, pointer.GetString(defaultOpts.Name)),
		authURL:        pointer.GetString(resolveURL(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *string { return o.AuthURL }, defaultOpts.OAuth2.AuthURL)),
		tokenURL:       pointer.GetString(resolveURL(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *string { return o.TokenURL }, defaultOpts.OAuth2.TokenURL)),
		revokeTokenURL: pointer.GetString(resolveURL(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *string { return o.RevocationURL }, defaultOpts.OAuth2.RevocationURL)),
		usePKCE:        pointer.GetBool(resolveUsePKCE(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *bool { return o.UsePKCE }, defaultOpts.OAuth2.UsePKCE)),
		extraAuth: pointer.Get(resolveExtraAuth(
			opts.OAuth2,
			func(o *oauthgotypes.OAuth2Options) *map[string]string { return o.ExtraAuth },
			defaultOpts.OAuth2.ExtraAuth,
		)),
	}
}

func buildOAuth2Provider(
	config *oAuth2OIDCProviderConfig,
	opts *oauthgotypes.OAuth2OIDCOptions,
	defaultOpts *oauthgotypes.OAuth2OIDCOptions,
) (coreprov.OAuthO2IDCProvider, error) {

	config.scopes = pointer.Get(resolveScopes(opts.OAuth2, func(o *oauthgotypes.OAuth2Options) *[]string { return o.Scopes }, defaultOpts.OAuth2.Scopes))
	provider := newOAuth2Provider(config)
	return coreprov.NewOAuth2OIDCFacade(provider, nil), nil
}

func buildOIDCProvider(
	config *oAuth2OIDCProviderConfig,
	opts *oauthgotypes.OAuth2OIDCOptions,
	defaultOpts *oauthgotypes.OAuth2OIDCOptions,
) (coreprov.OAuthO2IDCProvider, error) {

	config.scopes = pointer.Get(resolveOIDCScopes(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *[]string { return o.Scopes }, defaultOpts.OIDC.Scopes))
	config.skipIDTokenVerification = pointer.GetBool(resolveDisableIdTokenVerification(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *bool { return o.DisableIdTokenVerification }, defaultOpts.OIDC.DisableIdTokenVerification))

	provider := newOAuth2Provider(config)

	oidcDecorator, err := newOIDCDecorator(config, provider, opts, defaultOpts)
	if err != nil {
		return nil, err
	}

	return coreprov.NewOAuth2OIDCFacade(provider, oidcDecorator), nil
}

func newOAuth2Provider(config *oAuth2OIDCProviderConfig) oauthgoauth2.OAuth2Provider {
	return oauthgoauth2.NewStandardOAuth2Provider(config.name, oauthgoauth2.OAuth2Config{
		ClientID:      config.clientID,
		ClientSecret:  config.clientSecret,
		Scopes:        config.scopes,
		AuthURL:       config.authURL,
		TokenURL:      config.tokenURL,
		RevocationURL: config.revokeTokenURL,
		UsePKCE:       config.usePKCE,
		ExtraAuth:     config.extraAuth,
	})
}

func newOIDCDecorator(
	config *oAuth2OIDCProviderConfig,
	auth oauthgoauth2.OAuth2Provider,
	opts *oauthgotypes.OAuth2OIDCOptions,
	defaultOpts *oauthgotypes.OAuth2OIDCOptions,
) (*oidccore.OIDCDecorator, error) {

	issuer := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *string { return o.Issuer }, defaultOpts.OIDC.Issuer))
	jwksURL := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *string { return o.JWKSURL }, defaultOpts.OIDC.JWKSURL))
	uiURL := pointer.GetString(resolveOIDCURL(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *string { return o.UserInfoURL }, defaultOpts.OIDC.UserInfoURL))
	disableDiscovery := pointer.GetBool(resolveDisableDiscovery(opts.OIDC, func(o *oauthgotypes.OIDCOptions) *bool { return o.DisableDiscovery }, defaultOpts.OIDC.DisableDiscovery))

	return oidccore.NewOIDCDecorator(
		auth,
		oidccore.OIDCConfig{
			Issuer:                     issuer,
			JWKSURL:                    jwksURL,
			UserInfoURL:                uiURL,
			DisableDiscovery:           disableDiscovery,
			ClientID:                   config.clientID,
			DisableIdTokenVerification: config.skipIDTokenVerification,
		},
	)
}

// resolveMode resolves the mode.
func resolveMode(opts *oauthgotypes.OAuth2OIDCOptions, getter func(*oauthgotypes.OAuth2OIDCOptions) *oauthgotypes.Mode, defaultMode *oauthgotypes.Mode) *oauthgotypes.Mode {
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

func resolveExtraAuth(opts *oauthgotypes.OAuth2Options, getter func(*oauthgotypes.OAuth2Options) *map[string]string, defaultExtraAuth *map[string]string) *map[string]string {
	if opts != nil {
		if extraAuth := getter(opts); extraAuth != nil {
			return extraAuth
		}
	}
	return defaultExtraAuth
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
func resolveName(opts *oauthgotypes.OAuth2OIDCOptions, getter func(*oauthgotypes.OAuth2OIDCOptions) string, defaultName string) string {
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
