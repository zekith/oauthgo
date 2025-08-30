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
	oauthgoapple "github.com/zekith/oauthgo/provider/apple"
	oauthgoasana "github.com/zekith/oauthgo/provider/asana"
	oauthgoatlassian "github.com/zekith/oauthgo/provider/atlassian"
	oauthgoauth0 "github.com/zekith/oauthgo/provider/auth0"
	oauthgobitbucket "github.com/zekith/oauthgo/provider/bitbucket"
	oauthgobox "github.com/zekith/oauthgo/provider/box"
	oauthgoclickup "github.com/zekith/oauthgo/provider/clickup"
	oauthgodailymotion "github.com/zekith/oauthgo/provider/dailymotion"
	oauthgodigitalocean "github.com/zekith/oauthgo/provider/digitalocean"
	oauthgodiscord "github.com/zekith/oauthgo/provider/discord"
	oauthgodropbox "github.com/zekith/oauthgo/provider/dropbox"
	oauthgofacebook "github.com/zekith/oauthgo/provider/facebook"
	oauthgofigma "github.com/zekith/oauthgo/provider/figma"
	oauthgogitea "github.com/zekith/oauthgo/provider/gitea"
	oauthgogithub "github.com/zekith/oauthgo/provider/github"
	oauthgogitlab "github.com/zekith/oauthgo/provider/gitlab"
	oauthgogoogle "github.com/zekith/oauthgo/provider/google"
	oauthgoheroku "github.com/zekith/oauthgo/provider/heroku"
	oauthgoinstagram "github.com/zekith/oauthgo/provider/instagram"
	oauthgointercom "github.com/zekith/oauthgo/provider/intercom"
	oauthgoline "github.com/zekith/oauthgo/provider/line"
	oauthgolinkedin "github.com/zekith/oauthgo/provider/linkedin"
	oauthgomicrosoft "github.com/zekith/oauthgo/provider/microsoft"
	oauthgomiro "github.com/zekith/oauthgo/provider/miro"
	oauthgomonday "github.com/zekith/oauthgo/provider/monday"
	oauthgonotion "github.com/zekith/oauthgo/provider/notion"
	oauthgookta "github.com/zekith/oauthgo/provider/okta"
	oauthgopaypal "github.com/zekith/oauthgo/provider/paypal"
	oauthgoreddit "github.com/zekith/oauthgo/provider/reddit"
	oauthgosalesforce "github.com/zekith/oauthgo/provider/salesforce"
	oauthgoshopify "github.com/zekith/oauthgo/provider/shopify"
	oauthgoslack "github.com/zekith/oauthgo/provider/slack"
	oauthgospotify "github.com/zekith/oauthgo/provider/spotify"
	oauthgosquare "github.com/zekith/oauthgo/provider/square"
	oauthgostrava "github.com/zekith/oauthgo/provider/strava"
	oauthgostripe "github.com/zekith/oauthgo/provider/stripe"
	oauthgotiktok "github.com/zekith/oauthgo/provider/tiktok"
	oauthgotumblr "github.com/zekith/oauthgo/provider/tumblr"
	oauthgotwitch "github.com/zekith/oauthgo/provider/twitch"
	oauthgouber "github.com/zekith/oauthgo/provider/uber"
	oauthgox "github.com/zekith/oauthgo/provider/x"
	oauthgoxero "github.com/zekith/oauthgo/provider/xero"
	oauthgoyahoo "github.com/zekith/oauthgo/provider/yahoo"
	oauthgoyandex "github.com/zekith/oauthgo/provider/yandex"
	oauthgozoom "github.com/zekith/oauthgo/provider/zoom"
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

// initDependencies initializes the dependencies for the OAuthGo library
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

// setupOAuthProviders sets up the routes for the OAuth providers
// It also sets up the callback handlers for each provider
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
		{"clickup", oauthgoclickup.NewWithOptions, "CLICKUP_KEY", "CLICKUP_SECRET", nil, handler.AutoCallbackOAuth2},
		{"asana", oauthgoasana.NewWithOptions, "ASANA_KEY", "ASANA_SECRET", nil, handler.AutoCallbackOIDC},
		{"notion", oauthgonotion.NewWithOptions, "NOTION_KEY", "NOTION_SECRET", nil, handler.AutoCallbackOAuth2},
		{"twitch", oauthgotwitch.NewWithOptions, "TWITCH_KEY", "TWITCH_SECRET", nil, handler.AutoCallbackOIDC},
		{"zoom", oauthgozoom.NewWithOptions, "ZOOM_KEY", "ZOOM_SECRET", nil, handler.AutoCallbackOAuth2},
		{"paypal", oauthgopaypal.NewWithOptions, "PAYPAL_KEY", "PAYPAL_SECRET", pointer.To(map[string]string{"sandbox": "true"}), handler.AutoCallbackOAuth2},
		{"stripe", oauthgostripe.NewWithOptions, "STRIPE_KEY", "STRIPE_SECRET", nil, handler.AutoCallbackOAuth2},
		{"tumblr", oauthgotumblr.NewWithOptions, "TUMBLR_KEY", "TUMBLR_SECRET", nil, handler.AutoCallbackOAuth2},
		{"shopify", oauthgoshopify.NewWithOptions, "SHOPIFY_KEY", "SHOPIFY_SECRET", pointer.To(map[string]string{"shop": os.Getenv("SHOPIFY_SHOP")}), handler.AutoCallbackOAuth2},
		{"spotify", oauthgospotify.NewWithOptions, "SPOTIFY_KEY", "SPOTIFY_SECRET", nil, handler.AutoCallbackOAuth2},
		{"intercom", oauthgointercom.NewWithOptions, "INTERCOM_KEY", "INTERCOM_SECRET", nil, handler.AutoCallbackOAuth2},
		{"xero", oauthgoxero.NewWithOptions, "XERO_KEY", "XERO_SECRET", nil, handler.AutoCallbackOIDC},
		{"strava", oauthgostrava.NewWithOptions, "STRAVA_KEY", "STRAVA_SECRET", nil, handler.AutoCallbackOAuth2},
		{"dailymotion", oauthgodailymotion.NewWithOptions, "DAILYMOTION_KEY", "DAILYMOTION_SECRET", nil, handler.AutoCallbackOAuth2},
		{"heroku", oauthgoheroku.NewWithOptions, "HEROKU_KEY", "HEROKU_SECRET", nil, handler.AutoCallbackOAuth2},
		{"line", oauthgoline.NewWithOptions, "LINE_KEY", "LINE_SECRET", nil, handler.AutoCallbackOIDC},
		{"tiktok", oauthgotiktok.NewWithOptions, "TIKTOK_KEY", "TIKTOK_SECRET", nil, handler.AutoCallbackOIDC},
		{"uber", oauthgouber.NewWithOptions, "UBER_KEY", "UBER_SECRET", pointer.To(map[string]string{"domain": os.Getenv("UBER_DOMAIN")}), handler.AutoCallbackOAuth2},
		{"yahoo", oauthgoyahoo.NewWithOptions, "YAHOO_KEY", "YAHOO_SECRET", nil, handler.AutoCallbackOIDC},
		{"yandex", oauthgoyandex.NewWithOptions, "YANDEX_KEY", "YANDEX_SECRET", nil, handler.AutoCallbackOAuth2},
		{"apple", oauthgoapple.NewWithOptions, "APPLE_KEY", "APPLE_SECRET", nil, handler.AutoCallbackOAuth2},
	}

	for _, provider := range providers {
		if err := setupOAuthProvider(r, handler, provider.name, provider.factory, provider.keyEnv, provider.secretEnv, provider.extraConfig, provider.callbackFunc); err != nil {
			return err
		}
	}
	return nil
}

// setupUserInfoRoutes sets up the routes for the user info endpoints
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
		{"clickup", oauthgoclickup.GetUserInfoEndpoint(), "GET"},
		{"asana", oauthgoasana.GetUserInfoEndpoint(), "GET"},
		{"notion", oauthgonotion.GetUserInfoEndpoint(), "GET"},
		{"twitch", oauthgotwitch.GetUserInfoEndpoint(), "GET"},
		{"zoom", oauthgozoom.GetUserInfoEndpoint(), "GET"},
		{"paypal", oauthgopaypal.GetUserInfoEndpoint(true), "GET"},
		{"stripe", oauthgostripe.GetUserInfoEndpoint(), "GET"},
		{"tumblr", oauthgotumblr.GetUserInfoEndpoint(), "GET"},
		{"shopify", oauthgoshopify.GetUserInfoEndpoint(os.Getenv("SHOPIFY_SHOP")), "GET"},
		{"spotify", oauthgospotify.GetUserInfoEndpoint(), "GET"},
		{"intercom", oauthgointercom.GetUserInfoEndpoint(), "GET"},
		{"xero", oauthgoxero.GetUserInfoEndpoint(), "GET"},
		{"strava", oauthgostrava.GetUserInfoEndpoint(), "GET"},
		{"dailymotion", oauthgodailymotion.GetUserInfoEndpoint(), "GET"},
		{"heroku", oauthgoheroku.GetUserInfoEndpoint(), "GET"},
		{"line", oauthgoline.GetUserInfoEndpoint(), "GET"},
		{"tiktok", oauthgotiktok.GetUserInfoEndpoint(), "GET"},
		{"uber", oauthgouber.GetUserInfoEndpoint(os.Getenv("UBER_DOMAIN")), "GET"},
		{"yahoo", oauthgoyahoo.GetUserInfoEndpoint(), "GET"},
		{"yandex", oauthgoyandex.GetUserInfoEndpoint(), "GET"},
		{"apple", oauthgoapple.GetUserInfoEndpoint(), "GET"},
	}

	for _, userInfoProvider := range userInfoProviders {
		if userInfoProvider.name == "monday" {
			r.GET("/user/"+userInfoProvider.name, gin.WrapF(oauthgomonday.GetMondayUserInfoHandler()))
		} else if userInfoProvider.name == "notion" {
			r.GET("/user/"+userInfoProvider.name, gin.WrapF(oauthgonotion.GetNotionUserInfoHandler("")))
		} else if userInfoProvider.name == "intercom" {
			r.GET("/user/"+userInfoProvider.name, gin.WrapF(oauthgointercom.GetIntercomUserInfoHandler()))
		} else if userInfoProvider.name == "heroku" {
			r.GET("/user/"+userInfoProvider.name, gin.WrapF(oauthgoheroku.GetHerokuUserInfoHandler()))
		} else if userInfoProvider.name == "apple" {
			r.GET("/user/"+userInfoProvider.name, gin.WrapF(oauthgoapple.GetAppleUserInfoHandler()))
		} else {
			r.GET("/user/"+userInfoProvider.name, gin.WrapF(handler.UserInfo(userInfoProvider.userInfoEndpoint, userInfoProvider.method)))
		}
	}
}

// setupAPIRoutes sets up the API routes for the demo app
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

	if provider == "apple" {
		appleSecret, err := setupAppleClientSecret(clientID)
		if err != nil {
			fmt.Printf("Skipping apple provider: %v\n", err)
			return nil
		}
		clientSecret = appleSecret
	}

	isProviderAvailable := len(clientID) > 0 && len(clientSecret) > 0
	if !isProviderAvailable {
		fmt.Printf("Skipping %s provider because client ID and secret are not set\n", provider)
		return nil
	}

	oauthProvider, err := newProviderFunc(&coreprov.ProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ExtraConfig:  extraConfig,
	})
	if err != nil {
		return fmt.Errorf("failed to create %s provider: %w", provider, err)
	}

	handler.Register(provider, oauthProvider)
	baseUrl := os.Getenv("OAUTHGO_BASE_URL") + "/callback"

	// Mount routes using gin.WrapF to bridge http.HandlerFunc into Gin.
	r.GET("/auth/"+provider, gin.WrapF(handler.AutoLogin(baseUrl, provider)))
	r.GET("/callback/"+provider, gin.WrapF(callbackFunc(provider)))

	return nil
}

// setupAppleClientSecret handles Apple-specific client secret generation
func setupAppleClientSecret(clientID string) (string, error) {
	privateKey, err := oauthgoapple.LoadPrivateKey(os.Getenv("APPLE_PRIVATE_KEY"))
	if err != nil {
		return "", fmt.Errorf("private key loading failed: %w", err)
	}

	clientSecret, err := oauthgoapple.GenerateClientSecret(
		os.Getenv("APPLE_TEAM_ID"),
		clientID,
		os.Getenv("APPLE_KEY_ID"),
		privateKey,
	)
	if err != nil {
		return "", fmt.Errorf("client secret generation failed: %w", err)
	}
	if clientSecret == "" {
		return "", fmt.Errorf("client secret is empty")
	}

	return clientSecret, nil
}
