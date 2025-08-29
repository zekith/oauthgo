package main

import (
	"encoding/json"
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
	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostore "github.com/zekith/oauthgo/core/store"
	oauthgotypes "github.com/zekith/oauthgo/core/types"
	oauthgoslack "github.com/zekith/oauthgo/provider/slack"
)

const (
	serverPort        = ":3000"
	sessionCookieName = "oauthgo_session"
	sessionTTLDays    = 30
)

func main() {
	// Initialize the dependencies using Redis for session store and replay protection
	initDependencies()

	handler := oauthgo.HandlerFacade{}

	r := gin.Default()
	providerName := "slack"

	// Create and register the Slack OAuth2 provider
	provider, err := oauthgoslack.NewWithOptions(
		&oauthgotypes.ProviderConfig{
			ClientID:     os.Getenv("SLACK_KEY"),
			ClientSecret: os.Getenv("SLACK_SECRET"),
			OAuth2ODICOptions: &oauthgotypes.OAuth2OIDCOptions{
				//Mode:   pointer.To(oauthgotypes.OIDC), // Override defaults if needed
				OAuth2: &oauthgotypes.OAuth2Options{
					//Override defaults if needed
				},
			},
		})
	if err != nil {
		log.Fatal("failed to create slack provider: ", err)
	}
	handler.Register(providerName, provider)

	r.GET(fmt.Sprintf("/auth/%s", providerName), gin.WrapF(
		handler.Login(providerName, oauthgo.AuthURLOptions{
			RedirectURL: os.Getenv("OAUTHGO_BASE_URL") + "/callback/slack", // Your callback URL
		})),
	)

	r.GET(fmt.Sprintf("/callback/%s", providerName), gin.WrapF(
		handler.Callback(providerName, oauthgo.CallbackOptions{
			SetLoginCookie: true, // Set to true to enable session cookie
			SetSIDCookie:   true, // Set to true to enable session ID cookie
			StoreSession:   true, // Set to true to store a session in the session store
			OnError: func(w http.ResponseWriter, r *http.Request, err error) {
				// Handle the error appropriately
				http.Error(w, "oidc auto-callback failed: "+err.Error(), http.StatusInternalServerError)
			},
			OnSuccess: func(w http.ResponseWriter, r *http.Request, res *oauthgo.CallbackResult) {
				// For demo purposes, we return the user info and session data as JSON
				// In production; you might want to redirect the user to a different page
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":   "ok",
					"provider": res.ProviderName,
					"user":     res.User,
					"sid":      res.SID,
					"session":  res.Session,
				})
			},
		})),
	)

	log.Printf("listening on %s", serverPort)
	if err := r.Run(serverPort); err != nil {
		log.Fatal(err)
	}
}

func initDependencies() {

	deps := &authogodeps.OAuthGoDeps{
		ReplayProtector: oauthgoreplay.NewMemoryReplayProtector(),
		SessionStore:    oauthgostore.NewMemorySessionStore(),
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
