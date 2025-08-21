package oauthgooidc

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"

	"encoding/json"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	oauthgoauth2 "github.com/zekith/oauthgo/core/oauth2"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Issuer           string
	DisableDiscovery bool
	JWKSURL          string
	UserInfoURL      string // for discovery-less
	ClientID         string // pass explicitly, so we never need to "extract" it
}

type OIDCDecorator struct {
	base       oauthgoauth2.AuthorisationProvider // wrapped OAuth2 provider
	httpClient *http.Client
	verifier   *gooidc.IDTokenVerifier // non-nil in OIDC mode
	idp        *gooidc.Provider        // present when discovery is used
	cfg        OIDCConfig
}

func NewOIDCDecorator(base oauthgoauth2.AuthorisationProvider, httpClient *http.Client, cfg OIDCConfig) (*OIDCDecorator, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	d := &OIDCDecorator{base: base, httpClient: httpClient, cfg: cfg}
	// Build verifier
	ctx := gooidc.ClientContext(context.Background(), httpClient)
	if !cfg.DisableDiscovery {
		idp, err := gooidc.NewProvider(ctx, cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery: %w", err)
		}
		d.idp = idp
		d.verifier = idp.Verifier(&gooidc.Config{ClientID: cfg.ClientID})
	} else {
		if cfg.JWKSURL == "" {
			return nil, fmt.Errorf("DisableDiscovery=true requires JWKSURL")
		}
		ks := gooidc.NewRemoteKeySet(ctx, cfg.JWKSURL)
		d.verifier = gooidc.NewVerifier(cfg.Issuer, ks, &gooidc.Config{ClientID: cfg.ClientID})
	}
	return d, nil
}

func (d *OIDCDecorator) VerifyIDToken(ctx context.Context, raw string) error {
	if raw == "" || d.verifier == nil {
		return nil
	}
	_, err := d.verifier.Verify(ctx, raw)
	return err
}

// UserInfo retrieves user information either via ID token, discovery, or discovery-less mode.
func (d *OIDCDecorator) UserInfo(ctx context.Context, accessToken, idToken string) (*User, error) {
	var claims OIDCUserClaims

	if len(idToken) > 0 && d.verifier != nil {
		log.Println("Using ID Token to retrieve user info")
		parsed, err := d.verifier.Verify(ctx, idToken)
		if err != nil {
			return nil, fmt.Errorf("id token verify failed: %w", err)
		}
		if err := parsed.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse claims: %w", err)
		}
		return claims.ToUser(), nil
	}

	if d.idp != nil {
		log.Println("Using discovery provider to retrieve user info")
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
		ui, err := d.idp.UserInfo(gooidc.ClientContext(ctx, d.httpClient), ts)
		if err != nil {
			return nil, err
		}
		if err := ui.Claims(&claims); err != nil {
			return nil, err
		}
		return claims.ToUser(), nil
	}

	log.Println("Using discovery-less path to retrieve user info")
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

	if err := json.NewDecoder(res.Body).Decode(&claims); err != nil {
		return nil, err
	}
	return claims.ToUser(), nil
}
