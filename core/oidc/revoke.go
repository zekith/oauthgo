package oauthgooidc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"log"
)

// RevokeToken implements RFC 7009 token revocation.
// If clientSecret is empty, treats as a public client (PKCE) and uses no auth.
func RevokeToken(ctx context.Context, httpClient *http.Client, revocationURL, clientID, clientSecret, token, tokenTypeHint string) error {
	log.Println("Revoking token")
	if revocationURL == "" {
		return ErrRevocationUnsupported
	}
	// create revocation request
	req, err := createRevocationRequest(ctx, revocationURL, clientID, clientSecret, token, tokenTypeHint)
	if err != nil {
		log.Println("RevokeToken error creating request:", err)
		return err
	}

	// send revocation request
	res, err := httpClient.Do(req)
	if err != nil {
		log.Println("RevokeToken error:", err)
		return err
	}
	// close body
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(res.Body)

	// Successful revocation SHOULD return 200; some providers return 400 for unknown/expired token.
	if res.StatusCode == 200 || res.StatusCode == 400 {
		log.Println("Token revoked successfully", "status:", res.StatusCode)
		return nil
	}

	// Get error message
	b, _ := io.ReadAll(res.Body)
	return errors.New("revocation failed: status " + res.Status + ": " + string(b))
}

// createRevocationRequest creates a revocation request.
func createRevocationRequest(ctx context.Context, revocationURL, clientID, clientSecret, token, tokenTypeHint string) (*http.Request, error) {
	form := prepareRevocationForm(clientID, clientSecret, token, tokenTypeHint)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, revocationURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	return req, nil
}

// prepareRevocationForm prepares the revocation form.
func prepareRevocationForm(clientID, clientSecret, token, tokenTypeHint string) url.Values {
	form := url.Values{}
	form.Set("token", token)

	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}

	// For public clients (no secret), include client_id in form
	if clientSecret == "" {
		form.Set("client_id", clientID)
	}

	return form
}
