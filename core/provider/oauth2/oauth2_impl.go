package oauthgoauth2

import (
	"context"
	"encoding/json"
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
	UserInfoURL   string            // optional, provide if OIDC is not supported
	RevocationURL string            // optional RFC7009
	ExtraAuth     map[string]string // provider-specific params if needed
	ExtraToken    map[string]string // provider-specific params if needed
	UsePKCE       bool              // controls whether to use PKCE (Proof Key for Code Exchange) in the OAuth2 flow
}

// TokenExchangeResult contains the parsed token plus raw token response metadata.
type TokenExchangeResult struct {
	Token      *oauth2.Token
	RawBody    map[string]any
	RawHeaders map[string]string
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

func (p *StandardOAuth2Provider) UserInfoURL() string {
	return p.cfg.UserInfoURL
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

	// set return_to from query params
	if r.URL.Query() != nil {
		if r.URL.Query().Get("redirect_uri") != "" {
			opts.ReturnTo = r.URL.Query().Get("redirect_uri")
		}
		if r.URL.Query().Get("rd") != "" {
			opts.ReturnTo = r.URL.Query().Get("rd")
		}
		// set scopes from query params if present (comma-separated)
		if r.URL.Query().Get("scopes") != "" {
			scopeArr := strings.Split(r.URL.Query().Get("scopes"), ",")
			o.Scopes = scopeArr
			opts.Scopes = scopeArr
		}
	}

	statePayload, err := p.createStatePayload(opts)
	if err != nil {
		return "", "", err
	}
	queryParams := make(map[string]interface{}, len(r.URL.Query()))
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			queryParams[k] = v[0]
		}
	}
	statePayload.RequestParams = queryParams

	opaque, err := oauthgostate.GetStateCodec().Encode(statePayload)
	if err != nil {
		return "", "", err
	}

	params, err := p.buildAuthParams(opts, statePayload.PKCE)
	if err != nil {
		return "", "", err
	}

	codeURL := o.AuthCodeURL(opaque, params...)

	log.Printf("auth url: %s", codeURL)

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
		Provider:        p.name,
		Nonce:           nonce,
		CSRF:            csrf,
		ReturnTo:        opts.ReturnTo,
		PKCE:            pkce,
		Redirect:        opts.RedirectURL,
		IssuedAt:        time.Now().Unix(),
		Extras:          opts.Extras,
		RequestedScopes: opts.Scopes,
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

	res, err := p.exchangeCodeForToken(ctx, code, sp.Redirect, opts)
	if err != nil {
		return nil, err
	}

	return p.createSessionFromToken(ctx, res), nil
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
func (p *StandardOAuth2Provider) buildTokenExchangeOptions(sp *oauthgostate.StatePayload) (map[string]string, error) {
	opts := map[string]string{}

	if sp.PKCE != nil {
		opts["code_verifier"] = sp.PKCE.Verifier
	}

	for k, v := range p.cfg.ExtraToken {
		opts[k] = v
	}

	return opts, nil
}

// buildRefreshTokenOptions builds refresh token options.
func (p *StandardOAuth2Provider) buildRefreshTokenOptions() map[string]string {
	opts := map[string]string{}
	for k, v := range p.cfg.ExtraToken {
		opts[k] = v
	}
	return opts
}

// exchangeCodeForToken exchanges the code for a token and captures raw response data.
func (p *StandardOAuth2Provider) exchangeCodeForToken(
	ctx context.Context,
	code, redirectURL string,
	opts map[string]string,
) (*TokenExchangeResult, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURL)
	form.Set("client_id", p.cfg.ClientID)

	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	for k, v := range opts {
		form.Set(k, v)
	}

	return p.doTokenRequest(ctx, form, "failed to exchange code for token")
}

// doTokenRequest sends the token request and captures raw body and headers.
func (p *StandardOAuth2Provider) doTokenRequest(
	ctx context.Context,
	form url.Values,
	errPrefix string,
) (*TokenExchangeResult, error) {
	oauthConfig := p.cloneTemplateConfig()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		oauthConfig.Endpoint.TokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request: %w", errPrefix, err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errPrefix, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read response body: %w", errPrefix, err)
	}

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: http %d: %s", errPrefix, resp.StatusCode, string(bodyBytes))
	}

	rawBody := map[string]any{}
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &rawBody); err != nil {
			return nil, fmt.Errorf("%s: failed to parse response body: %w", errPrefix, err)
		}
	}

	rawHeaders := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		if len(v) > 0 {
			rawHeaders[k] = v[0]
		}
	}

	tok, err := tokenFromRawBody(rawBody)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to convert token response: %w", errPrefix, err)
	}

	return &TokenExchangeResult{
		Token:      tok,
		RawBody:    rawBody,
		RawHeaders: rawHeaders,
	}, nil
}

// createSessionFromToken creates the session from the token exchange result.
func (p *StandardOAuth2Provider) createSessionFromToken(ctx context.Context, res *TokenExchangeResult) *OAuth2Session {
	tok := res.Token

	idToken := oauthgoutils.StringValue(res.RawBody["id_token"])

	var grantedScopes []string
	if raw := oauthgoutils.StringValue(res.RawBody["scope"]); raw != "" {
		grantedScopes = strings.Fields(raw)
	}

	if len(grantedScopes) == 0 {
		if raw := headerValueCI(res.RawHeaders, "X-OAuth-RequestedScopes"); raw != "" {
			parts := strings.Split(raw, ",")
			grantedScopes = make([]string, 0, len(parts))
			for _, p := range parts {
				s := strings.TrimSpace(p)
				if s != "" {
					grantedScopes = append(grantedScopes, s)
				}
			}
		}
	}

	return &OAuth2Session{
		Provider:        p.name,
		AccessToken:     tok.AccessToken,
		RefreshToken:    tok.RefreshToken,
		TokenType:       tok.TokenType,
		Expiry:          tok.Expiry,
		IDToken:         idToken,
		RequestedScopes: p.cfg.Scopes,
		GrantedScopes:   grantedScopes,
		Raw: map[string]any{
			"token_response": res.RawBody,
			"headers":        res.RawHeaders,
		},
	}
}

// tokenFromRawBody converts a raw token response into oauth2.Token.
func tokenFromRawBody(raw map[string]any) (*oauth2.Token, error) {
	accessToken := oauthgoutils.StringValue(raw["access_token"])
	if accessToken == "" {
		return nil, fmt.Errorf("missing access_token in token response")
	}

	tok := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    oauthgoutils.StringValue(raw["token_type"]),
		RefreshToken: oauthgoutils.StringValue(raw["refresh_token"]),
	}

	if expiry, ok := parseExpiry(raw); ok {
		tok.Expiry = expiry
	}

	return tok, nil
}

// parseExpiry resolves expiry from either expiry or expires_in.
func parseExpiry(raw map[string]any) (time.Time, bool) {
	if v, ok := raw["expiry"]; ok {
		if s := oauthgoutils.StringValue(v); s != "" {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				return t, true
			}
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t, true
			}
		}
	}

	if v, ok := raw["expires_in"]; ok {
		if secs, ok := oauthgoutils.Int64Value(v); ok && secs > 0 {
			return time.Now().Add(time.Duration(secs) * time.Second), true
		}
	}

	return time.Time{}, false
}

// headerValueCI gets a header value from a simple map using case-insensitive matching.
func headerValueCI(headers map[string]string, key string) string {
	if v, ok := headers[key]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// Refresh implements the OAuth2Provider interface method and refreshes the token.
func (p *StandardOAuth2Provider) Refresh(ctx context.Context, refreshToken string) (*OAuth2Session, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", p.cfg.ClientID)

	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	for k, v := range p.buildRefreshTokenOptions() {
		form.Set(k, v)
	}

	res, err := p.doTokenRequest(ctx, form, "failed to refresh token")
	if err != nil {
		return nil, err
	}

	// Many providers do not return refresh_token during refresh. Preserve old one.
	if res.Token.RefreshToken == "" {
		res.Token.RefreshToken = refreshToken
		res.RawBody["refresh_token"] = refreshToken
	}

	return p.createSessionFromToken(ctx, res), nil
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

// GetState implements the OAuth2Provider interface method and gets the state.
func (p *StandardOAuth2Provider) GetState(ctx context.Context, opaqueState string) (*oauthgostate.StatePayload, error) {
	return p.validateAndDecodeState(opaqueState)
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
