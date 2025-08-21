package main

import (
	"log"
	"net/http"

	"github.com/zekith/oauthgo/core/bootstrap"
	"github.com/zekith/oauthgo/core/env"
	"github.com/zekith/oauthgo/examples/server/helper"
	"github.com/zekith/oauthgo/examples/server/providers"
)

func main() {
	// Initialize the core components of the OAuth server
	core := oauthgobootstrap.BuildCore()
	// Load environment configuration
	err := oauthgoenv.LoadDotEnv()

	if err != nil {
		log.Fatal(err)
	}
	// Initialize the OAuth manager
	err = oauthgoexamplesproviders.AddProviders(core)

	if err != nil {
		log.Fatalf("failed to add providers: %v", err)
	}

	// Setup HTTP handlers
	oauthgoexampleshelper.SetupHTTPHandlers(core.Manager, core.CookieMgr, core.SessionStore)

	// Start HTTP server
	addr := ":3000"
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
