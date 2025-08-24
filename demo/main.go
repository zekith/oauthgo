package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	oauthgo "github.com/zekith/oauthgo/api"
	oauthgocookie "github.com/zekith/oauthgo/core/cookie"
	authogodeps "github.com/zekith/oauthgo/core/deps"
	"github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostore "github.com/zekith/oauthgo/core/store"
	coreprov "github.com/zekith/oauthgo/core/types"
	oauthgogithub "github.com/zekith/oauthgo/provider/github"
	oauthgogoogle "github.com/zekith/oauthgo/provider/google"
	oauthgolinkedin "github.com/zekith/oauthgo/provider/linkedin"
	oauthgomicrosoft "github.com/zekith/oauthgo/provider/microsoft"
)

func main() {
	deps := &authogodeps.OAuthGoDeps{
		//ReplayProtector: oauthgoreplay.NewRedisReplayProtector(redisClient, "oauthgo:replay"),
		ReplayProtector: oauthgoreplay.NewMemoryReplayProtector(),
		//SessionStore:    oauthgostore.NewRedisSessionStore(redisClient, "oauthgo:session"),
		SessionStore: oauthgostore.NewMemorySessionStore(),
		//SessionCookieManager: oauthgocookie.GetDefaultHMACCookieSessionManager(),
		SessionCookieManager: &oauthgocookie.HMACSessionCookieManager{
			Name:       "oauthgo_session",
			Secret:     make([]byte, 0),
			TTL:        time.Hour * 24 * 30,
			Secure:     false,
			Domain:     "",
			HttpOnly:   true,
			CookiePath: "/",
			SameSite:   http.SameSiteLaxMode,
		},
	}
	// Initialize the dependencies
	authogodeps.Init(deps)

	// Initialize the handler facade
	handler := oauthgo.HandlerFacade{}

	if err := setupOAuthProvider(handler, "google", oauthgogoogle.NewWithOptions, "GOOGLE_KEY", "GOOGLE_SECRET", handler.AutoCallbackOAuth2); err != nil {
		log.Fatal(err)
	}

	if err := setupOAuthProvider(handler, "github", oauthgogithub.NewWithOptions, "GITHUB_KEY", "GITHUB_SECRET", handler.AutoCallbackOAuth2); err != nil {
		log.Fatal(err)
	}

	if err := setupOAuthProvider(handler, "linkedin", oauthgolinkedin.NewWithOptions, "LINKEDIN_KEY", "LINKEDIN_SECRET", handler.AutoCallbackOIDC); err != nil {
		log.Fatal(err)
	}

	if err := setupOAuthProvider(handler, "microsoft", oauthgomicrosoft.NewWithOptions, "MICROSOFT_KEY", "MICROSOFT_SECRET", handler.AutoCallbackOIDC); err != nil {
		log.Fatal(err)
	}

	// Optional prebuilt handlers
	http.HandleFunc("/me", handler.LoggedInUser())
	http.HandleFunc("/logout", handler.Logout())

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
	callbackFunc func(string) http.HandlerFunc,
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
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return fmt.Errorf("failed to create %s provider: %w", provider, err)
	}

	// Register the provider
	handler.Register(provider, providerFunc)

	// Register the login and callback handlers for the provider

	http.HandleFunc("/auth/"+provider, handler.AutoLogin(provider))
	http.HandleFunc("/callback/"+provider, callbackFunc(provider))

	return nil
}
