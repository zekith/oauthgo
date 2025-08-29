package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/AlekSi/pointer"
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
	oauthgoatlassian "github.com/zekith/oauthgo/provider/atlassian"
	oauthgoauth0 "github.com/zekith/oauthgo/provider/auth0"
	oauthgobitbucket "github.com/zekith/oauthgo/provider/bitbucket"
	oauthgobox "github.com/zekith/oauthgo/provider/box"
	oauthgodigitalocean "github.com/zekith/oauthgo/provider/digitalocean"
	oauthgodiscord "github.com/zekith/oauthgo/provider/discord"
	oauthgodropbox "github.com/zekith/oauthgo/provider/dropbox"
	oauthgofacebook "github.com/zekith/oauthgo/provider/facebook"
	oauthgofigma "github.com/zekith/oauthgo/provider/figma"
	oauthgogitea "github.com/zekith/oauthgo/provider/gitea"
	oauthgogithub "github.com/zekith/oauthgo/provider/github"
	oauthgogitlab "github.com/zekith/oauthgo/provider/gitlab"
	oauthgogoogle "github.com/zekith/oauthgo/provider/google"
	oauthgoinstagram "github.com/zekith/oauthgo/provider/instagram"
	oauthgolinkedin "github.com/zekith/oauthgo/provider/linkedin"
	oauthgomicrosoft "github.com/zekith/oauthgo/provider/microsoft"
	oauthgomiro "github.com/zekith/oauthgo/provider/miro"
	oauthgomonday "github.com/zekith/oauthgo/provider/monday"
	oauthgookta "github.com/zekith/oauthgo/provider/okta"
	oauthgoreddit "github.com/zekith/oauthgo/provider/reddit"
	oauthgosalesforce "github.com/zekith/oauthgo/provider/salesforce"
	oauthgoslack "github.com/zekith/oauthgo/provider/slack"
	oauthgosquare "github.com/zekith/oauthgo/provider/square"
	oauthgox "github.com/zekith/oauthgo/provider/x"
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
	setupUserInfoRoutes(r, handler)

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
		extraConfig  *map[string]string
		callbackFunc func(string) http.HandlerFunc
	}{
		{"google", oauthgogoogle.NewWithOptions, "GOOGLE_KEY", "GOOGLE_SECRET", nil, handler.AutoCallbackOIDC},
		{"github", oauthgogithub.NewWithOptions, "GITHUB_KEY", "GITHUB_SECRET", nil, handler.AutoCallbackOAuth2},
		{"linkedin", oauthgolinkedin.NewWithOptions, "LINKEDIN_KEY", "LINKEDIN_SECRET", nil, handler.AutoCallbackOIDC},
		{"microsoft", oauthgomicrosoft.NewWithOptions, "MICROSOFT_KEY", "MICROSOFT_SECRET", nil, handler.AutoCallbackOIDC},
		{"slack", oauthgoslack.NewWithOptions, "SLACK_KEY", "SLACK_SECRET", nil, handler.AutoCallbackOIDC},
		{"facebook", oauthgofacebook.NewWithOptions, "FACEBOOK_KEY", "FACEBOOK_SECRET", nil, handler.AutoCallbackOIDC},
		{"instagram", oauthgoinstagram.NewWithOptions, "INSTAGRAM_KEY", "INSTAGRAM_SECRET", nil, handler.AutoCallbackOAuth2},
		{"x", oauthgox.NewWithOptions, "X_KEY", "X_SECRET", nil, handler.AutoCallbackOAuth2},
		{"gitlab", oauthgogitlab.NewWithOptions, "GITLAB_KEY", "GITLAB_SECRET", nil, handler.AutoCallbackOIDC},
		{"box", oauthgobox.NewWithOptions, "BOX_KEY", "BOX_SECRET", nil, handler.AutoCallbackOIDC},
		{"dropbox", oauthgodropbox.NewWithOptions, "DROPBOX_KEY", "DROPBOX_SECRET", nil, handler.AutoCallbackOIDC},
		{"auth0", oauthgoauth0.NewWithOptions, "AUTH0_KEY", "AUTH0_SECRET", pointer.To(map[string]string{"domain": os.Getenv("AUTH0_DOMAIN")}), handler.AutoCallbackOIDC},
		{"okta", oauthgookta.NewWithOptions, "OKTA_KEY", "OKTA_SECRET", pointer.To(map[string]string{"domain": os.Getenv("OKTA_DOMAIN"), "authServer": os.Getenv("OKTA_AUTH_SERVER")}), handler.AutoCallbackOIDC},
		{"bitbucket", oauthgobitbucket.NewWithOptions, "BITBUCKET_KEY", "BITBUCKET_SECRET", nil, handler.AutoCallbackOAuth2},
		{"atlassian", oauthgoatlassian.NewWithOptions, "ATLASSIAN_KEY", "ATLASSIAN_SECRET", nil, handler.AutoCallbackOAuth2},
		{"digitalocean", oauthgodigitalocean.NewWithOptions, "DIGITALOCEAN_KEY", "DIGITALOCEAN_SECRET", nil, handler.AutoCallbackOAuth2},
		{"gitea", oauthgogitea.NewWithOptions, "GITEA_KEY", "GITEA_SECRET", nil, handler.AutoCallbackOIDC},
		{"salesforce", oauthgosalesforce.NewWithOptions, "SALESFORCE_KEY", "SALESFORCE_SECRET", nil, handler.AutoCallbackOIDC},
		{"discord", oauthgodiscord.NewWithOptions, "DISCORD_KEY", "DISCORD_SECRET", nil, handler.AutoCallbackOAuth2},
		{"reddit", oauthgoreddit.NewWithOptions, "REDDIT_KEY", "REDDIT_SECRET", nil, handler.AutoCallbackOAuth2},
		{"square", oauthgosquare.NewWithOptions, "SQUARE_KEY", "SQUARE_SECRET", pointer.To(map[string]string{"domain": os.Getenv("SQUARE_DOMAIN")}), handler.AutoCallbackOAuth2},
		{"figma", oauthgofigma.NewWithOptions, "FIGMA_KEY", "FIGMA_SECRET", nil, handler.AutoCallbackOAuth2},
		{"miro", oauthgomiro.NewWithOptions, "MIRO_KEY", "MIRO_SECRET", nil, handler.AutoCallbackOAuth2},
		{"monday", oauthgomonday.NewWithOptions, "MONDAY_KEY", "MONDAY_SECRET", nil, handler.AutoCallbackOAuth2},
	}

	for _, provider := range providers {
		if err := setupOAuthProvider(r, handler, provider.name, provider.factory, provider.keyEnv, provider.secretEnv, provider.extraConfig, provider.callbackFunc); err != nil {
			return err
		}
	}
	return nil
}

func setupUserInfoRoutes(r *gin.Engine, handler oauthgo.HandlerFacade) {
	userInfoProviders := []struct {
		name             string
		userInfoEndpoint string
		method           string
	}{
		{"github", oauthgogithub.GetUserInfoEndpoint(), "GET"},
		{"x", oauthgox.GetUserInfoEndpoint(), "GET"},
		{"gitlab", "https://gitlab.com/oauth/userinfo", "GET"},
		{"box", oauthgobox.GetUserInfoEndpoint(), "GET"},
		{"google", oauthgogoogle.GetUserInfoEndpoint(), "GET"},
		{"facebook", oauthgofacebook.GetUserInfoEndpoint(), "GET"},
		{"linkedin", oauthgolinkedin.GetUserInfoEndpoint(), "GET"},
		{"microsoft", oauthgomicrosoft.GetUserInfoEndpoint(), "GET"},
		{"slack", oauthgoslack.GetUserInfoEndpoint(), "GET"},
		{"dropbox", oauthgodropbox.GetUserInfoEndpoint(), "POST"},
		{"auth0", oauthgoauth0.GetUserInfoEndpoint(os.Getenv("AUTH0_DOMAIN")), "GET"},
		{"okta", oauthgookta.GetUserInfoEndpoint(os.Getenv("OKTA_DOMAIN"), os.Getenv("OKTA_AUTH_SERVER")), "GET"},
		{"bitbucket", oauthgobitbucket.GetUserInfoEndpoint(), "GET"},
		{"atlassian", oauthgoatlassian.GetUserInfoEndpoint(), "GET"},
		{"digitalocean", oauthgodigitalocean.GetUserInfoEndpoint(), "GET"},
		{"gitea", oauthgogitea.GetUserInfoEndpoint(), "GET"},
		{"salesforce", oauthgosalesforce.GetUserInfoEndpoint(), "GET"},
		{"discord", oauthgodiscord.GetUserInfoEndpoint(), "GET"},
		{"reddit", oauthgoreddit.GetUserInfoEndpoint(), "GET"},
		{"square", oauthgosquare.GetUserInfoEndpoint(os.Getenv("SQUARE_DOMAIN")), "GET"},
		{"figma", oauthgofigma.GetUserInfoEndpoint(), "GET"},
		{"miro", oauthgomiro.GetUserInfoEndpoint(), "GET"},
		{"monday", oauthgomonday.GetUserInfoEndpoint(), "GET"},
	}

	for _, userInfoProvider := range userInfoProviders {
		if userInfoProvider.name == "monday" {
			r.GET("/user/"+userInfoProvider.name, gin.WrapF(oauthgomonday.GetMondayUserInfoHandler()))
		} else {
			r.GET("/user/"+userInfoProvider.name, gin.WrapF(handler.UserInfo(userInfoProvider.userInfoEndpoint, userInfoProvider.method)))
		}
	}
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
	clientIDEnv string,
	clientSecretEnv string,
	extraConfig *map[string]string,
	callbackFunc func(string) http.HandlerFunc,
) error {
	clientID := os.Getenv(clientIDEnv)
	clientSecret := os.Getenv(clientSecretEnv)

	// Check if the client ID and secret are set
	// If the client ID and secret are not set, skip the provider
	if !(len(clientID) == 0 || len(clientSecret) == 0) {
		providerFunc, err := newProviderFunc(&coreprov.ProviderConfig{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			ExtraConfig:  extraConfig,
		})
		if err != nil {
			return fmt.Errorf("failed to create %s provider: %w", provider, err)
		}

		handler.Register(provider, providerFunc)
		baseUrl := os.Getenv("OAUTHGO_BASE_URL") + "/callback"

		// Mount routes using gin.WrapF to bridge http.HandlerFunc into Gin.
		r.GET("/auth/"+provider, gin.WrapF(handler.AutoLogin(baseUrl, provider)))
		r.GET("/callback/"+provider, gin.WrapF(callbackFunc(provider)))
	} else {
		fmt.Printf("Skipping %s provider because client ID and secret are not set\n", provider)
	}

	return nil
}
