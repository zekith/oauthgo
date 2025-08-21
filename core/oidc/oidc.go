package oauthgooidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	coreprovider "github.com/zekith/oauthgo/core/provider"
	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostate "github.com/zekith/oauthgo/core/state"
	oauthgoutils "github.com/zekith/oauthgo/core/utils"
	"golang.org/x/oauth2"
)

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const (
	DefaultScopeOpenID  = "openid"
	DefaultScopeProfile = "profile"
	DefaultScopeEmail   = "email"

	CodeChallengeParam       = "code_challenge"
	CodeChallengeMethodParam = "code_challenge_method"
	CodeVerifierParam        = "code_verifier"

	PromptParam    = "prompt"
	LoginHintParam = "login_hint"

	WellKnownPath         = "/.well-known/openid-configuration"
	RevocationEndpoint    = "revocation_endpoint"
	ErrorStateAlreadyUsed = "state already used"

	TokenTypeAccess = "access_token"

	DefaultNonceLength = 16
	DefaultCSRFLength  = 16
)

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

// OIDCConfig is the configuration for an OIDC provider.
type OIDCConfig struct {
	// Standard OIDC / OAuth2 fields
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string // extra scopes (in addition to "openid profile email")
	AuthURL      string   // optional override (used also for discovery-less providers)
	TokenURL     string   // optional override (used also for discovery-less providers)

	// Discovery-less mode (for providers with non-standard discovery paths, e.g. LinkedIn)
	DisableDiscovery bool
	JWKSURL          string // e.g., https://www.linkedin.com/oauth/openid/jwks
	UserInfoURL      string // e.g., https://api.linkedin.com/v2/userinfo
	RevocationURL    string // optional override (used if discovery is disabled or to override discovered value)

	SupportsPKCE *bool // whether the provider supports PKCE (RFC7636); defaults to true
}

// OIDCProvider is a reusable OIDC provider implementation.
type OIDCProvider struct {
	name          string
	cfg           OIDCConfig
	oauth         *oauth2.Config        // base config; clone per request before mutating
	verifier      *oidc.IDTokenVerifier // ID token verifier
	stateCodec    *oauthgostate.StateCodec
	replay        oauthgoreplay.ReplayProtector
	idp           *oidc.Provider // nil in discovery-less mode
	httpClient    *http.Client
	revocationURL string // resolved via discovery or explicit cfg
}

// -----------------------------------------------------------------------------
// Core Functions
// -----------------------------------------------------------------------------

// NewOIDCProvider constructs an OIDCProvider. Supports both discovery and discovery-less modes.
func NewOIDCProvider(
	name string,
	cfg OIDCConfig,
	stateCodec *oauthgostate.StateCodec,
	replay oauthgoreplay.ReplayProtector,
	httpClient *http.Client,
) (*OIDCProvider, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	ctx := oidc.ClientContext(context.Background(), httpClient)

	var (
		idp           *oidc.Provider
		verifier      *oidc.IDTokenVerifier
		oauth2Config  *oauth2.Config
		revocationURL string
		err           error
	)

	if !cfg.DisableDiscovery {
		// Standard path (Google, Microsoft, Salesforce, etc.)
		idp, err = oidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery (%s): %w", cfg.Issuer, err)
		}
		verifier = idp.Verifier(&oidc.Config{ClientID: cfg.ClientID})
		oauth2Config = createOAuth2Config(cfg, idp)
		// If explicit override is provided, prefer it; otherwise try to discover.
		if cfg.RevocationURL != "" {
			revocationURL = cfg.RevocationURL
		} else {
			revocationURL = discoverRevocationEndpoint(httpClient, cfg.Issuer)
		}
	} else {
		// Discovery-less path (e.g., LinkedIn's non-standard discovery location).
		if cfg.JWKSURL == "" || cfg.AuthURL == "" || cfg.TokenURL == "" || cfg.UserInfoURL == "" {
			return nil, fmt.Errorf("DisableDiscovery=true requires JWKSURL, AuthURL, TokenURL, and UserInfoURL")
		}
		ks := oidc.NewRemoteKeySet(ctx, cfg.JWKSURL)
		verifier = oidc.NewVerifier(cfg.Issuer, ks, &oidc.Config{ClientID: cfg.ClientID})
		oauth2Config = createOAuth2Config(cfg, nil) // endpoints from cfg
		revocationURL = cfg.RevocationURL           // may be empty if unsupported
	}

	return &OIDCProvider{
		name:          name,
		cfg:           cfg,
		oauth:         oauth2Config,
		verifier:      verifier,
		stateCodec:    stateCodec,
		replay:        replay,
		idp:           idp, // nil for discovery-less
		httpClient:    httpClient,
		revocationURL: revocationURL,
	}, nil
}

// Name returns the provider name (e.g., "google", "microsoft", "linkedin").
func (p *OIDCProvider) Name() string { return p.name }

// AuthURL produces the authorization URL and an encoded state payload.
func (p *OIDCProvider) AuthURL(ctx context.Context, r *http.Request, opts coreprovider.AuthOptions) (string, string, error) {
	oauth := p.cloneOAuth() // safe to mutate
	oauth.RedirectURL = opts.RedirectURL

	var pkce *oauthgoutils.PKCE
	var err error

	// If the provider explicitly does not support PKCE, set pkce to nil.
	if p.cfg.SupportsPKCE != nil && !*p.cfg.SupportsPKCE {
		pkce = nil
	} else {
		pkce, err = p.setupPKCE(opts.UsePKCE)
		if err != nil {
			return "", "", err
		}
	}

	nonce, err := oauthgoutils.RandomStringURLSafe(DefaultNonceLength)
	if err != nil {
		return "", "", err
	}
	csrf, err := oauthgoutils.RandomStringURLSafe(DefaultCSRFLength)
	if err != nil {
		return "", "", err
	}

	sp := oauthgostate.StatePayload{
		Provider: p.name,
		Nonce:    nonce,
		CSRF:     csrf,
		PKCE:     pkce,
		Redirect: opts.RedirectURL,
		IssuedAt: time.Now().Unix(),
		Extras:   opts.Extras,
	}
	encodedState, err := p.stateCodec.Encode(sp)
	if err != nil {
		return "", "", err
	}

	params := p.buildAuthParams(nonce, opts, pkce)

	if len(opts.Scopes) > 0 {
		oauth.Scopes = append([]string{DefaultScopeOpenID, DefaultScopeProfile, DefaultScopeEmail}, opts.Scopes...)
	}

	return oauth.AuthCodeURL(encodedState, params...), encodedState, nil
}

// Exchange performs the code exchange; also verifies ID token if present.
func (p *OIDCProvider) Exchange(ctx context.Context, r *http.Request, code, opaqueState string) (*coreprovider.Session, error) {
	sp, err := p.validateState(ctx, opaqueState)
	if err != nil {
		return nil, err
	}

	tok, err := p.exchangeTokenWithPKCE(ctx, code, sp)
	if err != nil {
		return nil, err
	}

	rawIDToken, _ := tok.Extra("id_token").(string)
	if err := p.verifyIDToken(ctx, rawIDToken); err != nil {
		return nil, err
	}

	return p.createSession(tok, rawIDToken), nil
}

// Refresh gets a new access token using the refresh token (if supported).
func (p *OIDCProvider) Refresh(ctx context.Context, refreshToken string) (*coreprovider.Session, error) {
	t := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.oauth.TokenSource(ctx, t)
	newTok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	rawIDToken, _ := newTok.Extra("id_token").(string)
	if err := p.verifyIDToken(ctx, rawIDToken); err != nil {
		return nil, err
	}
	if newTok.RefreshToken == "" {
		newTok.RefreshToken = refreshToken
	}
	return p.createSession(newTok, rawIDToken), nil
}

// UserInfo retrieves user information either via ID token, discovery, or discovery-less mode.
func (p *OIDCProvider) UserInfo(ctx context.Context, accessToken, idToken string) (*coreprovider.User, error) {
	var claims OIDCUserClaims

	if len(idToken) > 0 && p.verifier != nil {
		log.Println("Using ID Token to retrieve user info")
		parsed, err := p.verifier.Verify(ctx, idToken)
		if err != nil {
			return nil, fmt.Errorf("id token verify failed: %w", err)
		}
		if err := parsed.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse claims: %w", err)
		}
		return claims.ToUser(), nil
	}

	if p.idp != nil {
		log.Println("Using discovery provider to retrieve user info")
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
		ui, err := p.idp.UserInfo(oidc.ClientContext(ctx, p.httpClient), ts)
		if err != nil {
			return nil, err
		}
		if err := ui.Claims(&claims); err != nil {
			return nil, err
		}
		return claims.ToUser(), nil
	}

	log.Println("Using discovery-less path to retrieve user info")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	res, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: userinfo http %d", p.name, res.StatusCode)
	}

	if err := json.NewDecoder(res.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims.ToUser(), nil
}

// Revoke revokes an access token if a revocation endpoint is available.
func (p *OIDCProvider) Revoke(ctx context.Context, token string) error {
	return RevokeToken(ctx, p.httpClient, p.revocationURL, p.cfg.ClientID, p.cfg.ClientSecret, token, TokenTypeAccess)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func (p *OIDCProvider) cloneOAuth() *oauth2.Config {
	c := *p.oauth
	return &c
}

func (p *OIDCProvider) setupPKCE(usePKCE bool) (*oauthgoutils.PKCE, error) {
	if !usePKCE {
		return nil, nil
	}
	return oauthgoutils.NewPKCE()
}

func createOAuth2Config(cfg OIDCConfig, idp *oidc.Provider) *oauth2.Config {
	var endpoint oauth2.Endpoint
	switch {
	case cfg.AuthURL != "" && cfg.TokenURL != "":
		endpoint = oauth2.Endpoint{AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL}
	case idp != nil:
		endpoint = idp.Endpoint()
	default:
		panic("oidc: missing OAuth2 endpoints (no discovery and no AuthURL/TokenURL)")
	}
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       append([]string{DefaultScopeOpenID, DefaultScopeProfile, DefaultScopeEmail}, cfg.Scopes...),
		Endpoint:     endpoint,
	}
}

func (p *OIDCProvider) buildAuthParams(nonce string, opts coreprovider.AuthOptions, pkce *oauthgoutils.PKCE) []oauth2.AuthCodeOption {
	params := []oauth2.AuthCodeOption{oidc.Nonce(nonce)}
	if opts.Prompt != "" {
		params = append(params, oauth2.SetAuthURLParam(PromptParam, opts.Prompt))
	}
	if opts.LoginHint != "" {
		params = append(params, oauth2.SetAuthURLParam(LoginHintParam, opts.LoginHint))
	}
	if pkce != nil {
		params = append(params,
			oauth2.SetAuthURLParam(CodeChallengeParam, pkce.Challenge),
			oauth2.SetAuthURLParam(CodeChallengeMethodParam, pkce.Method),
		)
	}
	return params
}

func (p *OIDCProvider) validateState(ctx context.Context, opaqueState string) (oauthgostate.StatePayload, error) {
	sp, err := p.stateCodec.Decode(opaqueState)
	if err != nil {
		return oauthgostate.StatePayload{}, err
	}
	if p.replay != nil {
		if ok, err := p.replay.FirstSeen(ctx, opaqueState, p.stateCodec.TTL); err != nil {
			return oauthgostate.StatePayload{}, err
		} else if !ok {
			return oauthgostate.StatePayload{}, fmt.Errorf(ErrorStateAlreadyUsed)
		}
	}
	return sp, nil
}

func (p *OIDCProvider) exchangeTokenWithPKCE(ctx context.Context, code string, sp oauthgostate.StatePayload) (*oauth2.Token, error) {
	oauth := p.cloneOAuth()
	oauth.RedirectURL = sp.Redirect
	if sp.PKCE != nil {
		return oauth.Exchange(ctx, code, oauth2.SetAuthURLParam(CodeVerifierParam, sp.PKCE.Verifier))
	}
	return oauth.Exchange(ctx, code)
}

func (p *OIDCProvider) verifyIDToken(ctx context.Context, rawIDToken string) error {
	if rawIDToken == "" {
		return nil
	}
	if _, err := p.verifier.Verify(ctx, rawIDToken); err != nil {
		return fmt.Errorf("id_token verify: %w", err)
	}
	return nil
}

func (p *OIDCProvider) createSession(tok *oauth2.Token, rawIDToken string) *coreprovider.Session {
	return &coreprovider.Session{
		Provider:     p.name,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      rawIDToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
		Raw:          map[string]any{"oauth2_token": tok},
	}
}

func discoverRevocationEndpoint(httpClient *http.Client, issuer string) string {
	resp, err := httpClient.Get(issuer + WellKnownPath)
	if err != nil {
		return ""
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var metadata map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return ""
	}
	if v, ok := metadata[RevocationEndpoint].(string); ok {
		return v
	}
	return ""
}
