# oauthgo

*A lightweight and extensible Go library for OAuth2 and OpenID Connect (OIDC), designed for clarity, modularity, and production-grade security.
oauthgo simplifies authentication flows with built-in support for major identity [providers](#supported-providers), plug-and-play session and cookie stores, and robust defenses including PKCE, state/nonce validation, and replay protection — all while remaining unopinionated and compatible with any HTTP router or framework.*

> Repository: `github.com/zekith/oauthgo`

## Table of Contents

- [Why oauthgo?](#why-oauthgo)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Directory Layout](#directory-layout)
- [HTTP Handlers & Routing](#handler-facade)
- [Sessions & Cookies](#sessions--cookies)
- [Configuration](#configuration)
- [Adding a New Provider](#adding-a-new-provider)
- [Security Checklist](#security-checklist)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [Supported Providers](#supported-providers)
- [Development](#development)
- [License](#license)

---

## Why oauthgo?

`oauthgo` streamlines OAuth2 / OIDC flows without locking you into a specific web framework or storage engine.

- **First‑class OIDC** (Authorization Code + PKCE) with **fallback to OAuth2‑only** for providers that don’t implement
  OIDC.
- **Provider presets** (e.g., Google, Microsoft Entra ID, LinkedIn, Facebook, GitHub, SAP Concur, etc.) you can use
  as‑is or customize.
- **Add a new provider** Just register provider endpoints and scopes with core — no need to fork or modify the
  library.
- **Callback Flexibility**: Configure callback options and result backed by a solid foundation.
- **Pluggable sessions** (in‑memory or Redis) that you can swap without touching handler wiring.
- **Pluggable cookie manager** that you can swap without touching handler wiring.
- **Defense‑in‑depth**: state/nonce validation, PKCE, replay protection, and strict redirect handling.
- **Unopinionated routing**: plain `net/http` handlers, compatible with any mux or framework like gin.

> The repository currently contains `api/`, `core/`, `demo/`, and `provider/` packages at the top level.

---

## Features

- Authorization Code **+ PKCE** (recommended for web/public clients)
- **State & nonce** generation and verification
- **UserInfo** retrieval for OIDC and OAuth2‑only providers (via REST) when applicable
- **Session storage** abstractions (swap memory ↔ Redis in seconds)
- Supporting [50+ providers](#supported-providers) out-of-box
- Small, focused surface area; easy to extend for new providers

---

## Installation

```bash
go get github.com/zekith/oauthgo
```

Optionally, add Redis (for production‑ready shared sessions) in your app.

---

## Quick Start

Minimal server with Google OIDC

```go
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
	oauthgogoogle "github.com/zekith/oauthgo/provider/google"
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
	providerName := "google"

	// Create and register the Google OAuth2 provider
	provider, err := oauthgogoogle.NewWithOptions(
		&oauthgotypes.ProviderConfig{
			ClientID:     os.Getenv("GOOGLE_KEY"),
			ClientSecret: os.Getenv("GOOGLE_SECRET"),
			OAuth2ODICOptions: &oauthgotypes.OAuth2OIDCOptions{
				// Mode:   pointer.To(oauthgotypes.OIDC), // Override defaults if needed
				OAuth2: &oauthgotypes.OAuth2Options{
					// Override defaults if needed
				},
			},
		})
	if err != nil {
		log.Fatal("failed to create google provider: ", err)
	}
	handler.Register(providerName, provider)

	r.GET(fmt.Sprintf("/auth/%s", providerName), gin.WrapF(
		handler.Login(providerName, oauthgo.AuthURLOptions{
			RedirectURL: "http://localhost:3000/callback/google", // Your callback URL
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
		ReplayProtector: oauthgoreplay.NewMemoryReplayProtector(), // Use a redis replay protector in production
		SessionStore:    oauthgostore.NewMemorySessionStore(),     // Use a redis session store in production
		//SessionCookieManager: oauthgocookie.GetDefaultHMACCookieSessionManager(),
		SessionCookieManager: &oauthgocookie.HMACSessionCookieManager{
			Name:       sessionCookieName,
			Secret:     []byte(uuid.New()),
			TTL:        time.Hour * 24 * sessionTTLDays,
			Secure:     false, // Set to true in production
			Domain:     "",
			HttpOnly:   true,
			CookiePath: "/",
			SameSite:   http.SameSiteLaxMode,
		},
	}
	authogodeps.Init(deps)
}


```

---

## Core Concepts

### Providers & Options

Each provider is described using the `OAuth2OIDCOptions` struct, which includes the following key fields:

- **`Mode`**:  
  Specifies the authentication mode — either:
    - `OIDC` (OpenID Connect) or
    - `OAuth2Only` (for providers that don't support OIDC)

- **`OAuth2`**:  
  Contains OAuth2-specific configuration including:
    - Authorization and token endpoint URLs
    - Optional revocation endpoint
    - Scopes
    - PKCE (Proof Key for Code Exchange) flags

- **`OIDC`**:  
  Contains OIDC-specific configuration:
    - Issuer URL
    - Optional JWKS (JSON Web Key Set) URL
    - UserInfo endpoint URL

---

#### Notes:

- In most cases, you only need to **override scopes**. Endpoint URLs are preset in provider defaults but **can be overridden**.
- You can override **any field** in `OAuth2` and `OIDC`, except for a few **non-overridable fields** that are hardcoded in provider presets.
- If `Mode = OIDC`, the **OIDC scopes** are used for authorization and token requests.
- When overriding scopes via provider presets, **ensure that all required scopes are explicitly set**, as the override **completely replaces** the default scopes.

### Handler Facade

`HandlerFacade` orchestrates login and callback for all registered providers and exposes plug‑and‑play `net/http`
handlers:

- `Register(provider)` -> Registers the given provider.
- `Login(provider, authURLOptions)` → Builds authorization request (scopes, prompt, redirect), computes
  state/nonce/PKCE, and redirects to the provider.
- `Callback(provider, callbackOptions)` → Verifies state/nonce/PKCE, exchanges code, validates ID token (OIDC), fetches
  profile when configured, and persists the session. session.
- `UserInfo(userInfoEndpoint, method)` -> UserInfo returns a handler that fetches user info from the userinfo endpoint
  using the access token from the Authorization header.
- `Revoke(provider, token)` -> Revokes the given token using the provider's revocation endpoint.
- `Refresh(provider, refreshToken)` -> Refreshes the access token using the refresh token.
- `Logout()`  -> Logs out the current user by clearing the
- `LoggedInUser` -> Returns the currently logged in user. - `AutoLogin(baseUrl, provider)` -> Demo helper login handler.
- `AutoCallbackOIDC(provider)` -> Demo helper callback handler for OIDC providers.
- `AutoCallbackOAuth2(provider)` -> Demo helper callback handler for oAuth2 providers.

These handlers can be used in your own app to configure different routes or integrate with your web framework of choice.
Examples have been provided for [gin](demo/gin/multiproviders/main.go)
and [plainhttp](demo/plainhttp/multiproviders/main.go).

### Session Store & Cookie Manager

A `SessionStore` (memory/Redis) persists auth/session data while `CookieSessionManager` configures cookie attributes (
`Secure`, `HttpOnly`, `SameSite`, `MaxAge`).
You can swap these out for your own implementations.

---

### Callback Options and Result

Please use the `CallbackOptions` struct to configure the callback handler. You can set the following options:

- `SetLoginCookie`: Set to true to enable login cookie.
- `SetSIDCookie`: Set to true to enable session ID cookie.
- `StoreSession`: Set to true to store a session in the session store.
- `OnError`: Callback for errors.
- `OnSuccess`: Callback for successful callbacks.

Please refer [main.go](demo/gin/simple_memory/main.go) for a complete example.

## Directory Layout

```
.
├── api/            # optional API helpers & example wiring
├── core/           # provider manager, stores, cookies, types, shared utils
├── demo/           # runnable example app (e.g., local testing, Docker)
├── provider/       # provider presets (Google, Microsoft, LinkedIn, etc.)
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

> Exact contents may evolve, but the top‑level layout follows this structure.

---

## Sessions & Cookies

- **Memory**: Great for local development; not shared across instances.
- **Redis**: Recommended for production; enables horizontal scaling and sticky‑session‑free deployments.
- **Cookie**: `CookieSessionManager` controls cookie attributes; actual session payload lives in the store, not in the
  cookie.

---

## Configuration

Declare client credentials and callback URLs via environment variables or your config system. Example:

```env
# Google
GOOGLE_KEY=xxxx.apps.googleusercontent.com
GOOGLE_SECRET=super-secret

```

---

## Adding a New Provider

Provider presets are plain Go code returning `*otypes.OAuth2OIDCOptions`. For example, **Microsoft Entra ID (Azure AD)**
across tenants:

```go
package oauthgogoogle

import (
	"github.com/AlekSi/pointer"
	"github.com/zekith/oauthgo/core/provider/factory"
	coreprov "github.com/zekith/oauthgo/core/provider/oauth2oidc"
	"github.com/zekith/oauthgo/core/types"
)

var googleDefaults = &oauthgotypes.OAuth2OIDCOptions{
	Name: pointer.ToString("google"),
	Mode: pointer.To(oauthgotypes.OIDC), // Google strongly recommends OIDC

	OAuth2: &oauthgotypes.OAuth2Options{
		AuthURL:       pointer.ToString("https://accounts.google.com/o/oauth2/v2/auth"),
		TokenURL:      pointer.ToString("https://oauth2.googleapis.com/token"),
		RevocationURL: pointer.ToString("https://oauth2.googleapis.com/revoke"),
		Scopes:        pointer.To([]string{"email"}), // Applicable for OAuth2-only mode will be overridden by OIDC scopes if OIDC is enabled
		ExtraAuth: pointer.To(map[string]string{
			"access_type": "offline",
		}),
	},

	OIDC: &oauthgotypes.OIDCOptions{
		Issuer:      pointer.ToString("https://accounts.google.com"),
		Scopes:      pointer.To([]string{"openid", "profile", "email"}), // Applicable for OIDC mode
		UserInfoURL: pointer.ToString("https://openidconnect.googleapis.com/v1/userinfo"),
	},
}

func NewWithOptions(providerConfig *oauthgotypes.ProviderConfig) (coreprov.OAuthO2IDCProvider, error) {
	return oauthgofactory.NewOAuth2OIDCProvider(providerConfig, googleDefaults)
}

func GetUserInfoEndpoint() string {
	if googleDefaults.OIDC != nil && googleDefaults.OIDC.UserInfoURL != nil {
		return *googleDefaults.OIDC.UserInfoURL
	}
	return ""
}

```

Notes:

- OAuth2‑only providers (e.g., GitHub) typically omit `OIDCOptions` and instead define a `UserInfoURL` against the REST
  API.
- Use `offline_access` (or provider‑specific flag) when you need refresh tokens; not all providers issue them for web
  apps.

---

## Security Checklist

- [ ] **HTTPS only** in production; never transmit auth cookies over plaintext.
- [ ] **Validate state and (if OIDC) nonce**; refuse callbacks with mismatches.
- [ ] **Enable PKCE** for public clients; many providers support it.
- [ ] **Restrict redirect URIs** to a strict allowlist; reject open redirects.
- [ ] **Set secure cookie flags**: `Secure`, `HttpOnly`, `SameSite=Lax/Strict`, and sensible `MaxAge`.
- [ ] **Scope minimally**; request only what you need.
- [ ] **Handle token revocation** (RFC 7009) for providers that support it.
- [ ] **Log & rate‑limit callbacks** to mitigate abuse.

---

## Troubleshooting & FAQ

**“Something went wrong” after consent**
Ensure the callback URL you registered with the provider **exactly** matches the one your server exposes (scheme/host/port/path). Inspect state/nonce verification logs.

**“State parameter was modified”**
The stored state doesn’t match the callback. Clear cookies, ensure a centralized session store (e.g., Redis) across
instances, and verify that nothing overwrites the state between `/auth` and `/callback`.

**OIDC vs OAuth2‑only**
If a provider doesn’t support OIDC (no ID token), set `Mode = OAuth2Only`. You can still fetch user profile data via the
provider’s REST API when available.
Please note that OIDC supported providers will always return user response in User format as specified
in [oidc_provider.go](core/provider/oidc/oidc_provider.go) for consistency but
individual user endpoints output may vary depending on the provider. You need to take care of this when fetching user
data.

**When to use OIDC vs OAuth2**
Use OIDC if you plan to "log in user" with a particular identity provider (e.g., Google, Microsoft, Apple, etc.).
Use OAuth2 if you plan to access APIs on behalf of the user (e.g., GitHub, Dropbox, Box, etc.).

**What if a particular provider is not supported by oauthgo?**
You can register your own provider using core of `oauthgo` without modifying `oauthgo`. `oauthgo` it just
provides a convenient provider-specific default and a core facade to orchestrate login and callback.
Please refer[main.go](demo/gin/simple_memory/main.go) for a complete example.

At the same time, please open an issue or submit a pull request. We will add support for the provider as soon as
possible to help other users.

**What if I need to use authentication code flow outside oAuth2/OIDC?**
We do not plan to support this use case. This library is designed to be used with OAuth2/OIDC providers.

**What if the endpoints are changed or deprecated for a particular provider?**
You can always override the provider presets with your own.
Please open an issue or submit a pull request. We will update the provider presets as soon as possible to help other
users.

**Refresh tokens**
Some providers (e.g., LinkedIn, GitHub in certain flows) do **not** return refresh tokens for typical web apps. Use
short‑lived access tokens plus re‑auth, or provider‑specific grants if you need long‑lived access.

## Supported Providers

Some providers are in **beta** and may not be fully tested. Please report any issues and submit pull requests.
Please refer to this example for sample code: [multiproviders](demo/gin/multiproviders/main.go)
Each provider can be configured via environment variables or your config system and tested using the demo app by hitting
`/auth/{provider}` and `/callback/{provider}`. The demo app also serves as a reference implementation for your own app.
You need to register your own OAuth2/OIDC client credentials and callback URLs.

---

| Provider         | OAuth2 Support | OIDC Support | Refresh Tokens | Token Revocation | Remarks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:-----------------|:---------------|:-------------|:---------------|:-----------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Google           | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Microsoft        | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Okta             | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Auth0            | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| GitHub           | Yes            | No           | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| GitLab           | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Bitbucket        | Yes            | No           | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Atlassian        | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Box              | Yes            | Yes          | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Dropbox          | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Slack            | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Facebook         | Yes            | Yes          | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Instagram (Beta) | Yes            | No           | Yes            | No               | Could not test due to unavailability of a test environment. Community contributions are welcome—please help test this provider and submit a pull request to update the information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| LinkedIn         | Yes            | Yes          | Yes            | Yes              | LinkedIn generally grants 60‑day access tokens but does not issue refresh tokens for most applications; instead, you're expected to re-run the OAuth authorization flow when the access token nears expiration, and under ideal conditions (user still logged in and token not yet expired), LinkedIn can silently bypass the consent screen, resulting in a seamless refresh-like experience  However, programmatic refresh tokens are available—but only to approved Marketing Developer Platform partners—and these refresh tokens last up to 365 days, with the ability to exchange them for a new access token multiple times until they themselves expire learn.microsoft.com. In summary: for typical integrations, you're unable to refresh LinkedIn access tokens server‑side and must prompt users to reauthorize periodically; only privileged partners benefit from true refresh tokens and extended automated renewal. |
| Salesforce       | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| X (Twitter)      | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Discord          | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Dailymotion      | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Fitbit           | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Heroku           | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Intercom         | Yes            | No           | No             | No               | Access token has no automatic expiration (indefinite expiry). Manual revocation is required to invalidate it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Kakao            | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Line (Beta)      | Yes            | Yes          | Yes            | Yes              | Could not test due to unavailability of a test environment. Community contributions are welcome—please help test this provider and submit a pull request to update the information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| PayPal           | Yes            | No           | Yes            | No               | UserInfo Endpoint is not working in Sandbox enviorment, need to verify if it works in production env                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Reddit           | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Shopify (Beta)   | Yes            | No           | Yes            | No               | Could not test due to unavailability of a test environment. Community contributions are welcome—please help test this provider and submit a pull request to update the information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Spotify          | Yes            | No           | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Strava           | Yes            | No           | Yes            | Yes              | Was not able to specify more than one scope, giving error if more than one scope is specified.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Stripe (Beta)    | Yes            | No           | Yes            | Yes              | Could not test due to unavailability of a test environment. Community contributions are welcome—please help test this provider and submit a pull request to update the information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| TikTok (Beta)    | Yes            | No           | Yes            | Yes              | Could not test due to unavailability of a test environment. Community contributions are welcome—please help test this provider and submit a pull request to update the information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Tumblr           | Yes            | No           | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Uber (Beta)      | Yes            | No           | Yes            | Yes              | Could not test due to unavailability of a test environment. Community contributions are welcome—please help test this provider and submit a pull request to update the information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Xero             | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Yahoo            | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Yandex           | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Zoom             | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Apple (Beta)     | Yes            | Partial      | Yes            | Yes              | Could not test due to unavailability of a test environment. Community contributions are welcome—please help test this provider and submit a pull request to update the information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Twitch           | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Notion           | Yes            | No           | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Asana            | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ClickUp          | Yes            | No           | No             | No               | Access token has no automatic expiration (indefinite expiry). Manual revocation is required to invalidate it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Monday.com       | Yes            | No           | No             | No               | Access token has no automatic expiration (indefinite expiry). Manual revocation is required to invalidate it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Miro             | Yes            | No           | Yes            | Yes              | The availability of a refresh token depends on whether the OAuth2 application is configured to issue expiring access tokens. If token expiry is disabled, a refresh token may not be issued.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Figma            | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Square           | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| DigitalOcean     | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Gitea            | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Hubspot          | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Zoho             | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Docusign         | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Boldsign         | Yes            | Yes          | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Zendesk          | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Service Now      | Yes            | No           | Yes            | Yes              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Workday (Beta)   | Yes            | No           | Yes            | No               | Could not test due to unavailability of a test environment. Community contributions are welcome—please help test this provider and submit a pull request to update the information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Concur (Beta)    | Yes            | No           | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| AWS Cognito      | Yes            | Yes          | Yes            | No               |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Mailchimp        | Yes            | No           | No             | No               | Access token has no automatic expiration (indefinite expiry). Manual revocation is required to invalidate it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

## Development

```bash
# Run unit tests
go test ./...

# Static checks
go vet ./...
```

Project structure encourages adding providers under `/provider/...` and keeping protocol‑specific logic under
`/core/...`.

---

## License

MIT — see [LICENSE](./LICENSE).
