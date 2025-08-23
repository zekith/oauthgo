package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	oauthgo "github.com/zekith/oauthgo/api"
	"github.com/zekith/oauthgo/core/bootstrap"
	"github.com/zekith/oauthgo/core/provider/oauth2oidc"
	coreprov "github.com/zekith/oauthgo/core/types"
	oauthgogithub "github.com/zekith/oauthgo/provider/github"
	oauthgogoogle "github.com/zekith/oauthgo/provider/google"
)

func main() {
	// Initialize the core components of the OAuth server
	core := oauthgobootstrap.BuildCore()

	if err := setupOAuthProvider("google", oauthgogoogle.NewWithOptions, "GOOGLE_KEY", "GOOGLE_SECRET", core, oauthgo.AutoCallbackOIDC); err != nil {
		log.Fatal(err)
	}

	if err := setupOAuthProvider("github", oauthgogithub.NewWithOptions, "GITHUB_KEY", "GITHUB_SECRET", core, oauthgo.AutoCallbackOAuth2); err != nil {
		log.Fatal(err)
	}

	// Optional prebuilt handlers
	http.HandleFunc("/me", oauthgo.MeHandler("", core))
	http.HandleFunc("/logout", oauthgo.LogoutHandler("", core))

	// Start HTTP server
	addr := ":3000"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// setupOAuthProvider extracts the common pattern for configuring OAuth providers
// it is just a helper function for the demo, it is not part of the core library.
func setupOAuthProvider(
	providerName string,
	newProviderFunc func(*coreprov.ProviderInput) (oauth2oidc.OAuthO2IDCProvider, error),
	clientIDEnv, clientSecretEnv string,
	core *oauthgobootstrap.Core,
	callbackFunc func(string, *oauthgobootstrap.Core) http.HandlerFunc,
) error {
	clientID := os.Getenv(clientIDEnv)
	clientSecret := os.Getenv(clientSecretEnv)
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("%s: environment variables %s and %s must be set", providerName, clientIDEnv, clientSecretEnv)
	}

	provider, err := newProviderFunc(&coreprov.ProviderInput{
		StateCodec:      core.StateCodec,
		ReplayProtector: core.ReplayProtector,
		HttpClient:      core.HTTPClient,
		ClientID:        clientID,
		ClientSecret:    clientSecret,
	})
	if err != nil {
		return fmt.Errorf("failed to create %s provider: %w", providerName, err)
	}

	oauthgo.Register(providerName, provider)
	http.HandleFunc("/auth/"+providerName, oauthgo.AutoLogin(providerName))
	http.HandleFunc("/callback/"+providerName, callbackFunc(providerName, core))

	return nil
}
