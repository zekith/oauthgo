package oauthgoauth2

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	authogodeps "github.com/zekith/oauthgo/core/deps"
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

// StandardOAuth2Provider is an OAuth2 provider that implements the OAuth2Provider interface.
type StandardOAuth2Provider struct {
	name           string
	cfg            OAuth2Config
	templateConfig *oauth2.Config // template; clone per request
}

// NewStandardOAuth2Provider creates a new StandardOAuth2Provider.
func NewStandardOAuth2Provider(
	name string,
	cfg OAuth2Config,
) *StandardOAuth2Provider {

	scopes := getScopesWithDefaults(cfg.Scopes)
	oauth2Config := createOAuth2Config(cfg, scopes)

	return &StandardOAuth2Provider{
		name:           name,
		cfg:            cfg,
		templateConfig: oauth2Config,
	}
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
func (p *StandardOAuth2Provider) Name() string {
	return p.name
}

// cloneTemplateConfig returns a clone of the template config.
func (p *StandardOAuth2Provider) cloneTemplateConfig() *oauth2.Config {
	c := *p.templateConfig
	return &c
}

// AuthURL implements the OAuth2Provider interface method and returns the URL to redirect the user to for authentication.
func (p *StandardOAuth2Provider) AuthURL(ctx context.Context, r *http.Request, opts AuthURLOptions) (string, string, error) {
	o := p.cloneTemplateConfig()
	o.RedirectURL = opts.RedirectURL
	if len(opts.Scopes) > 0 {
		o.Scopes = append([]string{}, opts.Scopes...)
	}

	statePayload, err := p.createStatePayload(opts)
	if err != nil {
		return "", "", err
	}

	opaque, err := oauthgostate.GetStateCodec().Encode(statePayload)
	if err != nil {
		return "", "", err
	}

	params, err := p.buildAuthParams(opts, statePayload.PKCE)
	if err != nil {
		return "", "", err
	}

	codeURL := o.AuthCodeURL(opaque, params...)

	log.Println("auth url: %s", codeURL)
	return codeURL, opaque, nil
}

// createStatePayload creates the state payload.
func (p *StandardOAuth2Provider) createStatePayload(opts AuthURLOptions) (oauthgostate.StatePayload, error) {
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
func (p *StandardOAuth2Provider) buildAuthParams(opts AuthURLOptions, pkce *oauthgoutils.PKCE) ([]oauth2.AuthCodeOption, error) {
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

	for k, v := range opts.Extras {
		params = append(params, oauth2.SetAuthURLParam(k, v))
	}

	for k, v := range p.cfg.ExtraAuth {
		params = append(params, oauth2.SetAuthURLParam(k, v))
	}

	return params, nil
}

// Exchange implements the OAuth2Provider interface method and exchanges the code for a token.
func (p *StandardOAuth2Provider) Exchange(ctx context.Context, r *http.Request, code, opaque string) (*OAuth2Session, error) {
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
func (p *StandardOAuth2Provider) validateAndDecodeState(opaque string) (*oauthgostate.StatePayload, error) {
	sp, err := oauthgostate.GetStateCodec().Decode(opaque)
	if err != nil {
		return nil, fmt.Errorf("failed to decode state: %w", err)
	}
	return &sp, nil
}

// checkReplayProtection checks the replay protection.
func (p *StandardOAuth2Provider) checkReplayProtection(ctx context.Context, opaque string) error {
	if authogodeps.Get() == nil {
		return nil
	}

	isFirstSeen, err := authogodeps.Get().ReplayProtector.FirstSeen(ctx, opaque, oauthgostate.GetStateCodec().TTL)
	if err != nil {
		return fmt.Errorf("replay protection check failed: %w", err)
	}
	if !isFirstSeen {
		return fmt.Errorf("state already used")
	}
	return nil
}

// buildTokenExchangeOptions builds the token exchange options.
func (p *StandardOAuth2Provider) buildTokenExchangeOptions(sp *oauthgostate.StatePayload) ([]oauth2.AuthCodeOption, error) {
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
func (p *StandardOAuth2Provider) exchangeCodeForToken(ctx context.Context, code, redirectURL string, opts []oauth2.AuthCodeOption) (*oauth2.Token, error) {
	oauthConfig := p.cloneTemplateConfig()
	oauthConfig.RedirectURL = redirectURL

	tok, err := oauthConfig.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	return tok, nil
}

// createSessionFromToken creates the session from the token.
func (p *StandardOAuth2Provider) createSessionFromToken(tok *oauth2.Token) *OAuth2Session {
	idToken := ""
	if idTokenValue := tok.Extra("id_token"); idTokenValue != nil {
		idToken = fmt.Sprint(idTokenValue)
	}

	return &OAuth2Session{
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
func (p *StandardOAuth2Provider) Refresh(ctx context.Context, refreshToken string) (*OAuth2Session, error) {
	tok, err := p.refreshTokenFromSource(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	return p.createSessionFromToken(tok), nil
}

// refreshTokenFromSource refreshes the token from the source.
func (p *StandardOAuth2Provider) refreshTokenFromSource(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	o := p.cloneTemplateConfig()
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
func (p *StandardOAuth2Provider) Revoke(ctx context.Context, token string) error {
	if p.cfg.RevocationURL == "" {
		return nil
	}

	form := p.buildRevocationForm(token)
	req, err := p.createRevocationRequest(ctx, form)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	return p.handleRevocationResponse(res)
}

// buildRevocationForm builds the revocation form.
func (p *StandardOAuth2Provider) buildRevocationForm(token string) url.Values {
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	return form
}

// createRevocationRequest creates the revocation request.
func (p *StandardOAuth2Provider) createRevocationRequest(ctx context.Context, form url.Values) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.RevocationURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// handleRevocationResponse handles the revocation response.
func (p *StandardOAuth2Provider) handleRevocationResponse(res *http.Response) error {
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode/100 != 2 {
		return fmt.Errorf("revocation http %d", res.StatusCode)
	}
	return nil
}
