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
	handler := oauthgo.HandlerFacade{}

	// Initialize the core components of the OAuth server
	core := oauthgobootstrap.BuildCore()

	// Configure OAuth providers here

	if err := setupOAuthProvider(handler, "google", oauthgogoogle.NewWithOptions, "GOOGLE_KEY", "GOOGLE_SECRET", core, handler.AutoCallbackOIDC); err != nil {
		log.Fatal(err)
	}

	if err := setupOAuthProvider(handler, "github", oauthgogithub.NewWithOptions, "GITHUB_KEY", "GITHUB_SECRET", core, handler.AutoCallbackOAuth2); err != nil {
		log.Fatal(err)
	}

	// Optional prebuilt handlers
	http.HandleFunc("/me", handler.LoggedInUser(core))
	http.HandleFunc("/logout", handler.Logout(core))

	// Start HTTP server
	addr := ":3000"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// setupOAuthProvider extracts the common pattern for configuring OAuth providers
// it is just a helper function for the demo, it is not part of the core library.
func setupOAuthProvider(
	handler oauthgo.HandlerFacade,
	provider string,
	newProviderFunc func(*coreprov.ProviderConfig) (oauth2oidc.OAuthO2IDCProvider, error),
	clientIDEnv, clientSecretEnv string,
	core *oauthgobootstrap.Core,
	callbackFunc func(string, *oauthgobootstrap.Core) http.HandlerFunc,
) error {

	// Get the client ID and secret from environment variables
	clientID := os.Getenv(clientIDEnv)
	clientSecret := os.Getenv(clientSecretEnv)

	// Check if the client ID and secret are set
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("%s: environment variables %s and %s must be set", provider, clientIDEnv, clientSecretEnv)
	}

	// Create a new provider function from the provider config
	providerFunc, err := newProviderFunc(&coreprov.ProviderConfig{
		StateCodec:      core.StateCodec,
		ReplayProtector: core.ReplayProtector,
		HttpClient:      core.HTTPClient,
		ClientID:        clientID,
		ClientSecret:    clientSecret,
	})
	if err != nil {
		return fmt.Errorf("failed to create %s provider: %w", provider, err)
	}

	// Register the provider
	handler.Register(provider, providerFunc)

	// Register the login and callback handlers for the provider

	http.HandleFunc("/auth/"+provider, handler.AutoLogin(provider))
	http.HandleFunc("/callback/"+provider, callbackFunc(provider, core))

	return nil
}
