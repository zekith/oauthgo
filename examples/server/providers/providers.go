package oauthgoexamplesproviders

import (
	"fmt"
	"os"

	"github.com/zekith/oauthgo/core/bootstrap"
	"github.com/zekith/oauthgo/provider/linkedin"
)

// AddProviders adds all the OAuth providers to the OAuth manager.
func AddProviders(c *oauthgobootstrap.Core) error {
	if err := addLinkedIn(c); err != nil {
		return fmt.Errorf("failed to add LinkedIn provider: %w", err)
	}
	// Add other providers here as needed
	return nil
}

// addLinkedIn adds the LinkedIn provider to the OAuth manager.
func addLinkedIn(c *oauthgobootstrap.Core) error {
	clientID := os.Getenv("LINKEDIN_KEY")
	secret := os.Getenv("LINKEDIN_SECRET")
	if clientID == "" || secret == "" {
		return fmt.Errorf("LinkedIn: set LINKEDIN_KEY and LINKEDIN_SECRET")
	}
	p, err := oauthgolinkedin.New(c.StateCodec, c.ReplayProtector, c.HTTPClient, clientID, secret)
	if err != nil {
		return err
	}
	c.Manager.Providers[p.Name()] = p
	return nil
}
