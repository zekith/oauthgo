package oauthgoauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostate "github.com/zekith/oauthgo/core/state"
	oauthgoutils "github.com/zekith/oauthgo/core/utils"
	"golang.org/x/oauth2"
)

// OAuth2Config represents the configuration for the OAuth2 provider.
type OAuth2Config struct {
	ClientID      string            // required
	ClientSecret  string            // optional for public clients, required for confidential clients
	Scopes        []string          // scopes to request, defaults to "openid profile email"
	AuthURL       string            // optional, for discovery-based providers
	TokenURL      string            // optional, for discovery-based providers
	RevocationURL string            // optional RFC7009
	ExtraAuth     map[string]string // provider-specific params if needed
	ExtraToken    map[string]string // provider-specific params if needed
	UsePKCE       bool              // controls whether to use PKCE (Proof Key for Code Exchange) in the OAuth2 flow
}

// BaseOAuth2Provider is an OAuth2 provider that implements the OAuth2Provider interface.
type BaseOAuth2Provider struct {
	name       string
	cfg        OAuth2Config
	httpClient *http.Client
	stateCodec *oauthgostate.StateCodec
	replay     oauthgoreplay.ReplayProtector
	baseOAuth  *oauth2.Config // template; clone per request
}

// NewBaseOAuth2Provider creates a new BaseOAuth2Provider.
func NewBaseOAuth2Provider(
	name string,
	cfg OAuth2Config,
	st *oauthgostate.StateCodec,
	rp oauthgoreplay.ReplayProtector,
	hc *http.Client) *BaseOAuth2Provider {

	httpClient := getHTTPClientWithDefault(hc)
	scopes := getScopesWithDefaults(cfg.Scopes)
	oauth2Config := createOAuth2Config(cfg, scopes)

	return &BaseOAuth2Provider{
		name:       name,
		cfg:        cfg,
		httpClient: httpClient,
		stateCodec: st,
		replay:     rp,
		baseOAuth:  oauth2Config,
	}
}

// getHTTPClientWithDefault returns the default http client if hc is nil.
func getHTTPClientWithDefault(hc *http.Client) *http.Client {
	if hc == nil {
		return http.DefaultClient
	}
	return hc
}

// getScopesWithDefaults returns the default scopes if scopes is nil.
func getScopesWithDefaults(scopes []string) []string {
	if scopes == nil {
		return []string{"openid", "profile", "email"}
	}
	return slices.Clone(scopes)
}

// createOAuth2Config creates the OAuth2 config.
func createOAuth2Config(cfg OAuth2Config, scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
	}
}

// Name implements the OAuth2Provider interface method and returns the provider name.
func (p *BaseOAuth2Provider) Name() string {
	return p.name
}

// cloneOAuth returns a clone of the base OAuth2 config.
func (p *BaseOAuth2Provider) cloneOAuth() *oauth2.Config {
	c := *p.baseOAuth
	return &c
}

// AuthURL implements the OAuth2Provider interface method and returns the URL to redirect the user to for authentication.
func (p *BaseOAuth2Provider) AuthURL(ctx context.Context, r *http.Request, opts AuthOptions) (string, string, error) {
	o := p.cloneOAuth()
	o.RedirectURL = opts.RedirectURL
	if len(opts.Scopes) > 0 {
		o.Scopes = append([]string{}, opts.Scopes...)
	}

	statePayload, err := p.createStatePayload(opts)
	if err != nil {
		return "", "", err
	}

	opaque, err := p.stateCodec.Encode(statePayload)
	if err != nil {
		return "", "", err
	}

	params, err := p.buildAuthParams(opts, statePayload.PKCE)
	if err != nil {
		return "", "", err
	}

	codeURL := o.AuthCodeURL(opaque, params...)
	return codeURL, opaque, nil
}

// createStatePayload creates the state payload.
func (p *BaseOAuth2Provider) createStatePayload(opts AuthOptions) (oauthgostate.StatePayload, error) {
	nonce, err := oauthgoutils.RandomStringURLSafe(16)
	if err != nil {
		return oauthgostate.StatePayload{}, err
	}

	csrf, err := oauthgoutils.RandomStringURLSafe(16)
	if err != nil {
		return oauthgostate.StatePayload{}, err
	}

	var pkce *oauthgoutils.PKCE
	if p.cfg.UsePKCE {
		pkce, err = oauthgoutils.NewPKCE()
		if err != nil {
			return oauthgostate.StatePayload{}, err
		}
	}

	return oauthgostate.StatePayload{
		Provider: p.name,
		Nonce:    nonce,
		CSRF:     csrf,
		PKCE:     pkce,
		Redirect: opts.RedirectURL,
		IssuedAt: time.Now().Unix(),
		Extras:   opts.Extras,
	}, nil
}

// buildAuthParams builds the auth params.
func (p *BaseOAuth2Provider) buildAuthParams(opts AuthOptions, pkce *oauthgoutils.PKCE) ([]oauth2.AuthCodeOption, error) {
	var params []oauth2.AuthCodeOption

	if opts.Prompt != "" {
		params = append(params, oauth2.SetAuthURLParam("prompt", opts.Prompt))
	}
	if opts.LoginHint != "" {
		params = append(params, oauth2.SetAuthURLParam("login_hint", opts.LoginHint))
	}

	if pkce != nil {
		params = append(params,
			oauth2.SetAuthURLParam("code_challenge", pkce.Challenge),
			oauth2.SetAuthURLParam("code_challenge_method", pkce.Method),
		)
	}

	for k, v := range p.cfg.ExtraAuth {
		params = append(params, oauth2.SetAuthURLParam(k, v))
	}

	return params, nil
}

// Exchange implements the OAuth2Provider interface method and exchanges the code for a token.
func (p *BaseOAuth2Provider) Exchange(ctx context.Context, r *http.Request, code, opaque string) (*Session, error) {
	sp, err := p.validateAndDecodeState(opaque)
	if err != nil {
		return nil, err
	}

	if err := p.checkReplayProtection(ctx, opaque); err != nil {
		return nil, err
	}

	opts, err := p.buildTokenExchangeOptions(sp)
	if err != nil {
		return nil, err
	}

	tok, err := p.exchangeCodeForToken(ctx, code, sp.Redirect, opts)
	if err != nil {
		return nil, err
	}

	return p.createSessionFromToken(tok), nil
}

// validateAndDecodeState validates and decodes the state.
func (p *BaseOAuth2Provider) validateAndDecodeState(opaque string) (*oauthgostate.StatePayload, error) {
	sp, err := p.stateCodec.Decode(opaque)
	if err != nil {
		return nil, fmt.Errorf("failed to decode state: %w", err)
	}
	return &sp, nil
}

// checkReplayProtection checks the replay protection.
func (p *BaseOAuth2Provider) checkReplayProtection(ctx context.Context, opaque string) error {
	if p.replay == nil {
		return nil
	}

	isFirstSeen, err := p.replay.FirstSeen(ctx, opaque, p.stateCodec.TTL)
	if err != nil {
		return fmt.Errorf("replay protection check failed: %w", err)
	}
	if !isFirstSeen {
		return fmt.Errorf("state already used")
	}
	return nil
}

// buildTokenExchangeOptions builds the token exchange options.
func (p *BaseOAuth2Provider) buildTokenExchangeOptions(sp *oauthgostate.StatePayload) ([]oauth2.AuthCodeOption, error) {
	var opts []oauth2.AuthCodeOption

	if sp.PKCE != nil {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", sp.PKCE.Verifier))
	}

	for k, v := range p.cfg.ExtraToken {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}

	return opts, nil
}

// exchangeCodeForToken exchanges the code for a token.
func (p *BaseOAuth2Provider) exchangeCodeForToken(ctx context.Context, code, redirectURL string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	oauthConfig := p.cloneOAuth()
	oauthConfig.RedirectURL = redirectURL

	tok, err := oauthConfig.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return tok, nil
}

// createSessionFromToken creates the session from the token.
func (p *BaseOAuth2Provider) createSessionFromToken(tok *oauth2.Token) *Session {
	idToken := ""
	if idTokenValue := tok.Extra("id_token"); idTokenValue != nil {
		idToken = fmt.Sprint(idTokenValue)
	}

	return &Session{
		Provider:     p.name,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
		IDToken:      idToken,
		Raw:          map[string]any{"oauth2_token": tok},
	}
}

// Refresh implements the OAuth2Provider interface method and refreshes the token.
func (p *BaseOAuth2Provider) Refresh(ctx context.Context, refreshToken string) (*Session, error) {
	tok, err := p.refreshTokenFromSource(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	return p.createSessionFromToken(tok), nil
}

// refreshTokenFromSource refreshes the token from the source.
func (p *BaseOAuth2Provider) refreshTokenFromSource(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	o := p.cloneOAuth()
	ts := o.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return tok, nil
}

// Revoke implements the OAuth2Provider interface method and revokes the token.
func (p *BaseOAuth2Provider) Revoke(ctx context.Context, token string) error {
	if p.cfg.RevocationURL == "" {
		return nil
	}

	form := p.buildRevocationForm(token)
	req, err := p.createRevocationRequest(ctx, form)
	if err != nil {
		return err
	}

	res, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}

	return p.handleRevocationResponse(res)
}

// buildRevocationForm builds the revocation form.
func (p *BaseOAuth2Provider) buildRevocationForm(token string) url.Values {
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	return form
}

// createRevocationRequest creates the revocation request.
func (p *BaseOAuth2Provider) createRevocationRequest(ctx context.Context, form url.Values) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.RevocationURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// handleRevocationResponse handles the revocation response.
func (p *BaseOAuth2Provider) handleRevocationResponse(res *http.Response) error {
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode/100 != 2 {
		return fmt.Errorf("revocation http %d", res.StatusCode)
	}
	return nil
}
