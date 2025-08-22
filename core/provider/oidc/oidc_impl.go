package oauthgooidc

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"

	"encoding/json"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/zekith/oauthgo/core/provider/oauth2"
	"golang.org/x/oauth2"
)

// OIDCConfig represents the configuration for the OIDC provider.
type OIDCConfig struct {
	Issuer                     string
	DisableDiscovery           bool
	DisableIdTokenVerification bool
	JWKSURL                    string
	UserInfoURL                string // for discovery-less
	ClientID                   string // pass explicitly, so we never need to "extract" it
}

// OIDCDecorator wraps an OAuth2 provider and adds OIDC-specific functionality.
type OIDCDecorator struct {
	base       oauthgoauth2.OAuth2Provider // wrapped OAuth2 provider
	httpClient *http.Client
	verifier   *gooidc.IDTokenVerifier // non-nil in OIDC mode
	idp        *gooidc.Provider        // present when discovery is used
	cfg        OIDCConfig
}

// NewOIDCDecorator creates a new OIDCDecorator.
func NewOIDCDecorator(base oauthgoauth2.OAuth2Provider, httpClient *http.Client, cfg OIDCConfig) (*OIDCDecorator, error) {
	httpClient = initializeHTTPClient(httpClient)

	d := &OIDCDecorator{
		base:       base,
		httpClient: httpClient,
		cfg:        cfg,
	}

	verifier, idp, err := createVerifier(httpClient, cfg)
	if err != nil {
		return nil, err
	}

	d.verifier = verifier
	d.idp = idp

	return d, nil
}

// initializeHTTPClient initializes the HTTP client.
func initializeHTTPClient(httpClient *http.Client) *http.Client {
	if httpClient == nil {
		return http.DefaultClient
	}
	return httpClient
}

// createVerifier creates the ID token verifier.
func createVerifier(httpClient *http.Client, cfg OIDCConfig) (*gooidc.IDTokenVerifier, *gooidc.Provider, error) {
	if cfg.DisableIdTokenVerification {
		return nil, nil, nil // disable verification
	}

	ctx := gooidc.ClientContext(context.Background(), httpClient)

	if !cfg.DisableDiscovery {
		return createVerifierWithDiscovery(ctx, cfg)
	}

	return createVerifierWithoutDiscovery(ctx, cfg)
}

// createVerifierWithDiscovery creates the ID token verifier using OIDC discovery.
func createVerifierWithDiscovery(ctx context.Context, cfg OIDCConfig) (*gooidc.IDTokenVerifier, *gooidc.Provider, error) {
	idp, err := gooidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}

	verifier := idp.Verifier(&gooidc.Config{ClientID: cfg.ClientID})
	return verifier, idp, nil
}

// createVerifierWithoutDiscovery creates the ID token verifier without OIDC discovery.
func createVerifierWithoutDiscovery(ctx context.Context, cfg OIDCConfig) (*gooidc.IDTokenVerifier, *gooidc.Provider, error) {
	if cfg.JWKSURL == "" {
		return nil, nil, fmt.Errorf("DisableDiscovery=true requires JWKSURL")
	}

	ks := gooidc.NewRemoteKeySet(ctx, cfg.JWKSURL)
	verifier := gooidc.NewVerifier(cfg.Issuer, ks, &gooidc.Config{ClientID: cfg.ClientID})
	return verifier, nil, nil
}

// VerifyIDToken implements the OIDCDecorator interface and verifies the ID token.
func (d *OIDCDecorator) VerifyIDToken(ctx context.Context, raw string) error {
	if raw == "" || d.verifier == nil {
		return nil
	}
	_, err := d.verifier.Verify(ctx, raw)
	return err
}

// UserInfo implements the OIDCDecorator interface and retrieves user information.
func (d *OIDCDecorator) UserInfo(ctx context.Context, accessToken, idToken string) (*User, error) {
	if len(idToken) > 0 && d.verifier != nil {
		return d.userInfoFromIDToken(ctx, idToken)
	}
	if d.idp != nil {
		return d.userInfoFromDiscovery(ctx, accessToken)
	}
	return d.userInfoFromHTTP(ctx, accessToken)
}

// userInfoFromIDToken retrieves user information by verifying and parsing the ID token.
func (d *OIDCDecorator) userInfoFromIDToken(ctx context.Context, idToken string) (*User, error) {
	log.Println("Using ID Token to retrieve user info")

	parsed, err := d.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("id token verify failed: %w", err)
	}

	var claims OIDCUserClaims
	if err := parsed.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims.ToUser(), nil
}

// userInfoFromDiscovery retrieves user information using the OIDC discovery provider.
func (d *OIDCDecorator) userInfoFromDiscovery(ctx context.Context, accessToken string) (*User, error) {
	log.Println("Using discovery provider to retrieve user info")

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	ui, err := d.idp.UserInfo(gooidc.ClientContext(ctx, d.httpClient), ts)
	if err != nil {
		return nil, err
	}

	var claims OIDCUserClaims
	if err := ui.Claims(&claims); err != nil {
		return nil, err
	}

	return claims.ToUser(), nil
}

// userInfoFromHTTP retrieves user information via direct HTTP request in discovery-less mode.
func (d *OIDCDecorator) userInfoFromHTTP(ctx context.Context, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: userinfo http %d", d.base.Name(), res.StatusCode)
	}

	var claims OIDCUserClaims
	if err := json.NewDecoder(res.Body).Decode(&claims); err != nil {
		return nil, err
	}

	return claims.ToUser(), nil
}
