package oauthgoexamplesproviders

import (
	"fmt"
	"os"

	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/bootstrap"
	coreprov "github.com/zekith/oauthgo/core/provider"
	oauthgogoogle "github.com/zekith/oauthgo/provider/google"
	"github.com/zekith/oauthgo/provider/linkedin"
)

// AddProviders adds all the OAuth providers to the OAuth manager.
func AddProviders(c *oauthgobootstrap.Core) error {
	if err := addLinkedIn(c); err != nil {
		return fmt.Errorf("failed to add LinkedIn provider: %w", err)
	}
	if err := addGoogle(c); err != nil {
		return fmt.Errorf("failed to add Google provider: %w", err)
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

	input := &coreprov.ProviderInput{
		StateCodec:      c.StateCodec,
		ReplayProtector: c.ReplayProtector,
		HttpClient:      c.HTTPClient,
		ClientID:        clientID,
		ClientSecret:    secret,
		Options: &coreprov.ProviderOptions{
			Name:   pointer.ToString("linkedin"),
			Mode:   pointer.To(coreprov.OIDC),
			OAuth2: &coreprov.OAuth2Options{}, // leave empty to use provider defaults
			OIDC:   &coreprov.OIDCOptions{},   // leave empty to use discovery defaults
		},
	}

	p, err := oauthgolinkedin.NewWithOptions(input)
	if err != nil {
		return err
	}
	c.Manager.Providers[p.Name()] = p
	return nil
}

func addGoogle(c *oauthgobootstrap.Core) error {
	clientID := os.Getenv("GOOGLE_KEY")
	secret := os.Getenv("GOOGLE_SECRET")
	if clientID == "" || secret == "" {
		return fmt.Errorf("Google: set GOOGLE_KEY and GOOGLE_SECRET")
	}
	// if input Options are not set, the provider will use the default values
	input := &coreprov.ProviderInput{
		StateCodec:      c.StateCodec,
		ReplayProtector: c.ReplayProtector,
		HttpClient:      c.HTTPClient,
		ClientID:        clientID,
		ClientSecret:    secret,
	}

	p, err := oauthgogoogle.NewWithOptions(input)
	if err != nil {
		return err
	}
	c.Manager.Providers[p.Name()] = p
	return nil
}
