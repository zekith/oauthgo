package oauthgoauth2

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostate "github.com/zekith/oauthgo/core/state"
	oauthgoutils "github.com/zekith/oauthgo/core/utils"
	"golang.org/x/oauth2"
)

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

type BaseOAuth2Provider struct {
	name       string
	cfg        OAuth2Config
	httpClient *http.Client
	stateCodec *oauthgostate.StateCodec
	replay     oauthgoreplay.ReplayProtector
	baseOAuth  *oauth2.Config // template; clone per request
}

func NewBaseOAuth2Provider(
	name string,
	cfg OAuth2Config,
	st *oauthgostate.StateCodec,
	rp oauthgoreplay.ReplayProtector,
	hc *http.Client) *BaseOAuth2Provider {
	if hc == nil {
		hc = http.DefaultClient
	}
	if cfg.Scopes == nil {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	return &BaseOAuth2Provider{
		name:       name,
		cfg:        cfg,
		httpClient: hc,
		stateCodec: st,
		replay:     rp,
		baseOAuth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Scopes:       append([]string{}, cfg.Scopes...),
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.AuthURL,
				TokenURL: cfg.TokenURL,
			},
		},
	}
}

func (p *BaseOAuth2Provider) Name() string               { return p.name }
func (p *BaseOAuth2Provider) cloneOAuth() *oauth2.Config { c := *p.baseOAuth; return &c }

func (p *BaseOAuth2Provider) AuthURL(ctx context.Context, r *http.Request, opts AuthOptions) (string, string, error) {
	o := p.cloneOAuth()
	o.RedirectURL = opts.RedirectURL
	if len(opts.Scopes) > 0 {
		o.Scopes = append([]string{}, opts.Scopes...)
	}

	nonce, _ := oauthgoutils.RandomStringURLSafe(16) // harmless in OAuth2-only; used by OIDC decorator if present
	csrf, _ := oauthgoutils.RandomStringURLSafe(16)
	var pkce *oauthgoutils.PKCE
	// PKCE is optional in OAuth2, but if the provider supports it, we use it
	if opts.UsePKCE && p.cfg.UsePKCE {
		fmt.Println("Using PKCE for OAuth2 flow")
		pkce, _ = oauthgoutils.NewPKCE()
	}

	sp := oauthgostate.StatePayload{Provider: p.name, Nonce: nonce, CSRF: csrf, PKCE: pkce, Redirect: opts.RedirectURL, IssuedAt: time.Now().Unix(), Extras: opts.Extras}
	opaque, err := p.stateCodec.Encode(sp)
	if err != nil {
		return "", "", err
	}

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
	codeURL := o.AuthCodeURL(opaque, params...)
	return codeURL, opaque, nil
}

func (p *BaseOAuth2Provider) Exchange(ctx context.Context, r *http.Request, code, opaque string) (*Session, error) {
	sp, err := p.stateCodec.Decode(opaque)
	if err != nil {
		return nil, err
	}
	if p.replay != nil {
		if ok, err := p.replay.FirstSeen(ctx, opaque, p.stateCodec.TTL); err != nil {
			return nil, err
		} else if !ok {
			return nil, fmt.Errorf("state already used")
		}
	}
	o := p.cloneOAuth()
	o.RedirectURL = sp.Redirect
	var opts []oauth2.AuthCodeOption
	if sp.PKCE != nil {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", sp.PKCE.Verifier))
	}
	for k, v := range p.cfg.ExtraToken {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}

	tok, err := o.Exchange(ctx, code, opts...)
	if err != nil {
		fmt.Println("Error exchanging code for token:", err)
		return nil, err
	}

	return &Session{
		Provider:     p.name,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
		IDToken:      fmt.Sprint(tok.Extra("id_token")), // often empty in OAuth2
		Raw:          map[string]any{"oauth2_token": tok},
	}, nil
}

func (p *BaseOAuth2Provider) Refresh(ctx context.Context, refreshToken string) (*Session, error) {
	o := p.cloneOAuth()
	ts := o.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshToken
	}
	return &Session{
		Provider:     p.name,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
		IDToken:      fmt.Sprint(tok.Extra("id_token")),
		Raw:          map[string]any{"oauth2_token": tok},
	}, nil
}

func (p *BaseOAuth2Provider) Revoke(ctx context.Context, token string) error {
	log.Println("Revoking token for revocation URL:", p.cfg.RevocationURL)
	if p.cfg.RevocationURL == "" {
		return nil
	}

	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.RevocationURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := p.httpClient.Do(req)
	if err != nil {
		log.Println("Error revoking token:", err)
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("revocation http %d", res.StatusCode)
	}
	log.Println("Token revoked")
	return nil
}
