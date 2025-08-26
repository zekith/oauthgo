package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pborman/uuid"
	oauthgo "github.com/zekith/oauthgo/api"
	oauthgocookie "github.com/zekith/oauthgo/core/cookie"
	authogodeps "github.com/zekith/oauthgo/core/deps"
	"github.com/zekith/oauthgo/core/provider/oauth2oidc"
	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostore "github.com/zekith/oauthgo/core/store"
	coreprov "github.com/zekith/oauthgo/core/types"
	helpers "github.com/zekith/oauthgo/demo"
	oauthgogithub "github.com/zekith/oauthgo/provider/github"
	oauthgogoogle "github.com/zekith/oauthgo/provider/google"
	oauthgolinkedin "github.com/zekith/oauthgo/provider/linkedin"
	oauthgomicrosoft "github.com/zekith/oauthgo/provider/microsoft"
)

const (
	serverPort        = ":3000"
	sessionCookieName = "oauthgo_session"
	sessionTTLDays    = 30
)

type RefreshRequest struct {
	Provider     string `json:"provider" binding:"required"`
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RevokeRequest struct {
	Provider string `json:"provider" binding:"required"`
	Token    string `json:"token" binding:"required"`
}

func main() {
	initDependencies()

	handler := oauthgo.HandlerFacade{}
	r := gin.Default()

	if err := setupOAuthProviders(r, handler); err != nil {
		log.Fatal(err)
	}

	setupAPIRoutes(r, handler)

	log.Printf("listening on %s", serverPort)
	if err := r.Run(serverPort); err != nil {
		log.Fatal(err)
	}
}

func initDependencies() {

	// Using Redis for session store and replay protection
	if os.Getenv("REDIS_HOST") == "" || os.Getenv("REDIS_USERNAME") == "" || os.Getenv("REDIS_PASSWORD") == "" {
		log.Fatal("REDIS_HOST, REDIS_USERNAME, and REDIS_PASSWORD must be set in the env variables")
	}
	redisClient := helpers.NewRedisClient(
		os.Getenv("REDIS_HOST"),
		os.Getenv("REDIS_USERNAME"),
		os.Getenv("REDIS_PASSWORD"),
		"",
	)
	deps := &authogodeps.OAuthGoDeps{
		ReplayProtector: oauthgoreplay.NewRedisReplayProtector(redisClient, "oauthgo:replay"),
		SessionStore:    oauthgostore.NewRedisSessionStore(redisClient, "oauthgo:session"),
		SessionCookieManager: &oauthgocookie.HMACSessionCookieManager{
			Name:       sessionCookieName,
			Secret:     []byte(uuid.New()),
			TTL:        time.Hour * 24 * sessionTTLDays,
			Secure:     false,
			Domain:     "",
			HttpOnly:   true,
			CookiePath: "/",
			SameSite:   http.SameSiteLaxMode,
		},
	}
	authogodeps.Init(deps)
}

func setupOAuthProviders(r *gin.Engine, handler oauthgo.HandlerFacade) error {
	providers := []struct {
		name         string
		factory      func(*coreprov.ProviderConfig) (oauth2oidc.OAuthO2IDCProvider, error)
		keyEnv       string
		secretEnv    string
		callbackFunc func(string) http.HandlerFunc
	}{
		{"google", oauthgogoogle.NewWithOptions, "GOOGLE_KEY", "GOOGLE_SECRET", handler.AutoCallbackOIDC},
		{"github", oauthgogithub.NewWithOptions, "GITHUB_KEY", "GITHUB_SECRET", handler.AutoCallbackOAuth2},
		{"linkedin", oauthgolinkedin.NewWithOptions, "LINKEDIN_KEY", "LINKEDIN_SECRET", handler.AutoCallbackOIDC},
		{"microsoft", oauthgomicrosoft.NewWithOptions, "MICROSOFT_KEY", "MICROSOFT_SECRET", handler.AutoCallbackOIDC},
	}

	for _, provider := range providers {
		if err := setupOAuthProvider(r, handler, provider.name, provider.factory, provider.keyEnv, provider.secretEnv, provider.callbackFunc); err != nil {
			return err
		}
	}
	return nil
}

func setupAPIRoutes(r *gin.Engine, handler oauthgo.HandlerFacade) {
	r.GET("/me", gin.WrapF(handler.LoggedInUser()))
	r.GET("/logout", gin.WrapF(handler.Logout()))

	r.POST("/refresh", func(c *gin.Context) {
		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "provider and refresh_token are required"})
			return
		}
		handler.Refresh(req.Provider, req.RefreshToken)(c.Writer, c.Request)
	})

	r.POST("/revoke", func(c *gin.Context) {
		var req RevokeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "provider and token are required"})
			return
		}
		handler.Revoke(req.Provider, req.Token)(c.Writer, c.Request)
	})
}

// setupOAuthProvider extracts the common pattern for configuring OAuth providers
func setupOAuthProvider(
	r *gin.Engine,
	handler oauthgo.HandlerFacade,
	provider string,
	newProviderFunc func(*coreprov.ProviderConfig) (oauth2oidc.OAuthO2IDCProvider, error),
	clientIDEnv, clientSecretEnv string,
	callbackFunc func(string) http.HandlerFunc,
) error {
	clientID := os.Getenv(clientIDEnv)
	clientSecret := os.Getenv(clientSecretEnv)
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("%s: environment variables %s and %s must be set", provider, clientIDEnv, clientSecretEnv)
	}

	providerFunc, err := newProviderFunc(&coreprov.ProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return fmt.Errorf("failed to create %s provider: %w", provider, err)
	}

	handler.Register(provider, providerFunc)
	baseUrl := "http://localhost" + serverPort + "/callback"

	// Mount routes using gin.WrapF to bridge http.HandlerFunc into Gin.
	r.GET("/auth/"+provider, gin.WrapF(handler.AutoLogin(baseUrl, provider)))
	r.GET("/callback/"+provider, gin.WrapF(callbackFunc(provider)))
	return nil
}
