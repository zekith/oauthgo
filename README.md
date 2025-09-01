
# oauthgo

*A lightweight, extensible Go library for implementing OAuth2 and OpenID Connect (OIDC) with major identity providers. Built for clarity, composability, and production‑grade security (PKCE, state/nonce, replay protection) with pluggable session stores.*

> Repository: `github.com/zekith/oauthgo`

## Table of Contents
- [Why oauthgo?](#why-oauthgo)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [Directory Layout](#directory-layout)
- [HTTP Handlers & Routing](#http-handlers--routing)
- [Sessions & Cookies](#sessions--cookies)
- [Configuration](#configuration)
- [End-to-End Example](#end-to-end-example)
- [Adding a New Provider](#adding-a-new-provider)
- [Security Checklist](#security-checklist)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [Development](#development)
- [Roadmap](#roadmap)
- [License](#license)

---

## Why oauthgo?
`oauthgo` streamlines OAuth2 / OIDC flows without locking you into a specific web framework or storage engine.

- **First‑class OIDC** (Authorization Code + PKCE) with **fallback to OAuth2‑only** for providers that don’t implement OIDC.
- **Provider presets** (e.g., Google, Microsoft Entra ID, LinkedIn, Facebook, GitHub, SAP Concur, etc.) you can use as‑is or customize.
- **Pluggable sessions** (in‑memory or Redis) that you can swap without touching handler wiring.
- **Defense‑in‑depth**: state/nonce validation, PKCE, replay protection, and strict redirect handling.
- **Unopinionated routing**: plain `net/http` handlers, compatible with any mux or framework.

> The repository currently contains `api/`, `core/`, `demo/`, and `provider/` packages at the top level.

---

## Features

- Authorization Code **+ PKCE** (recommended for web/public clients)
- **State & nonce** generation and verification
- **UserInfo** retrieval for OIDC and OAuth2‑only providers (via REST) when applicable
- **Session storage** abstractions (swap memory ↔ Redis in seconds)
- Small, focused surface area; easy to extend for new providers

---

## Installation

```bash
go get github.com/zekith/oauthgo
```

Optionally add Redis (for production‑ready shared sessions) in your app.

---

## Quick Start

Minimal server with Google + Microsoft sign‑in using Authorization Code + PKCE:

```go
package main

import (
    "log"
    "net/http"

    oauthcookie "github.com/zekith/oauthgo/core/cookie"
    oauthstore  "github.com/zekith/oauthgo/core/store"
    coreprov    "github.com/zekith/oauthgo/core/provider"

    provfactory "github.com/zekith/oauthgo/core/provider/factory"
    oidcprov    "github.com/zekith/oauthgo/core/provider/oauth2oidc"
    otypes      "github.com/zekith/oauthgo/core/types"
)

func main() {
    // 1) Provider manager
    pm := coreprov.NewProviderManager()

    // Google preset (explicit values shown for clarity)
    google := &otypes.OAuth2OIDCOptions{
        Name: otypes.String("google"),
        Mode: otypes.ToMode(otypes.OIDC),
        OAuth2: &otypes.OAuth2Options{
            AuthURL:  otypes.String("https://accounts.google.com/o/oauth2/v2/auth"),
            TokenURL: otypes.String("https://oauth2.googleapis.com/token"),
            Scopes:   otypes.Strings([]string{"openid", "email", "profile"}),
            UsePKCE:  otypes.Bool(true),
        },
        OIDC: &otypes.OIDCOptions{
            Issuer:      otypes.String("https://accounts.google.com"),
            UserInfoURL: otypes.String("https://openidconnect.googleapis.com/v1/userinfo"),
        },
    }

    // Microsoft (multi‑tenant). See “Adding a New Provider” for a helper.
    msft := buildMicrosoftDefaults("common")

    pm.MustRegister("google", oidcprov.New(google))
    pm.MustRegister("microsoft", oidcprov.New(msft))

    // 2) Sessions & cookies
    cookieMgr := oauthcookie.NewCookieSessionManager(oauthcookie.Options{
        CookieName: "oauthgo_session",
        Secure:     true,
        HTTPOnly:   true,
        SameSite:   http.SameSiteLaxMode,
    })
    sessStore := oauthstore.NewMemoryStore() // swap with Redis in prod

    // 3) Routes: /auth/{provider} and /callback/{provider}
    http.HandleFunc("/auth/", pm.LoginHandler(func(r *http.Request) coreprov.AuthOptions {
        return coreprov.AuthOptions{
            RedirectURL: defaultRedirect(r), // where to send the user after login
            UsePKCE:     true,
            Prompt:      "select_account",
            ExtraAuth:   map[string]string{"access_type": "offline"}, // ask for refresh token if supported
        }
    }))

    http.HandleFunc("/callback/", pm.CallbackHandler(cookieMgr, sessStore))

    http.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
        // Load user info / claims from session and render response
        w.WriteHeader(http.StatusOK)
        _, _ = w.Write([]byte("ok"))
    })

    log.Println("listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## Core Concepts

### Providers & Options
Each provider is described by `OAuth2OIDCOptions`:
- `Mode`: `OIDC` or `OAuth2Only`
- `OAuth2`: authorization, token, (optional revocation) endpoints, scopes, PKCE flags
- `OIDC`: issuer, (optional JWKS URL), userinfo URL

### Provider Manager
`ProviderManager` orchestrates login and callback for all registered providers and exposes two plug‑and‑play `net/http` handlers:

- `LoginHandler(getAuthOptions)` → Builds authorization request (scopes, prompt, redirect), computes state/nonce/PKCE, and redirects to the provider.
- `CallbackHandler(cookieMgr, sessionStore)` → Verifies state/nonce/PKCE, exchanges code, validates ID token (OIDC), fetches profile when configured, and persists the session.

### Session Store & Cookie Manager
A `SessionStore` (memory/Redis) persists auth/session data while `CookieSessionManager` configures cookie attributes (`Secure`, `HttpOnly`, `SameSite`, `MaxAge`).

---

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
└── docker-compose.yml
```

> Exact contents may evolve, but the top‑level layout follows this structure.

---

## HTTP Handlers & Routing

**`/auth/{provider}`**  
Redirects the user to the provider’s consent screen using options from your `LoginHandler` closure (scopes, prompt, redirect URL, PKCE on/off, extra params).

**`/callback/{provider}`**  
Handles the OAuth2/OIDC callback, validates all defenses, stores the session, and finally redirects the user to your `RedirectURL` (e.g., `/me`).

---

## Sessions & Cookies

- **Memory**: Great for local development; not shared across instances.
- **Redis**: Recommended for production; enables horizontal scaling and sticky‑session‑free deployments.
- **Cookie**: `CookieSessionManager` controls cookie attributes; actual session payload lives in the store, not in the cookie.

---

## Configuration

Declare client credentials and callback URLs via environment variables or your config system. Example:

```env
# Google
OAUTHGO_GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com
OAUTHGO_GOOGLE_CLIENT_SECRET=super-secret
OAUTHGO_GOOGLE_REDIRECT_URL=http://localhost:8080/callback/google

# Microsoft (multi‑tenant)
OAUTHGO_MSFT_CLIENT_ID=…
OAUTHGO_MSFT_CLIENT_SECRET=…
OAUTHGO_MSFT_TENANT=common
OAUTHGO_MSFT_REDIRECT_URL=http://localhost:8080/callback/microsoft

# Redis (optional)
REDIS_URL=redis://localhost:6379
```

---

## End-to-End Example

Mount the two core handlers and expose a protected `GET /me` endpoint. Tune per‑request parameters in the `AuthOptions` closure.

```go
http.HandleFunc("/auth/", pm.LoginHandler(func(r *http.Request) coreprov.AuthOptions {
    return coreprov.AuthOptions{
        RedirectURL: defaultRedirect(r),
        UsePKCE:     true,
        Prompt:      "select_account",
        ExtraAuth:   map[string]string{"access_type": "offline"},
    }
}))

http.HandleFunc("/callback/", pm.CallbackHandler(cookieMgr, sessStore))
```

---

## Adding a New Provider

Provider presets are plain Go code returning `*otypes.OAuth2OIDCOptions`. For example, **Microsoft Entra ID (Azure AD)** across tenants:

```go
package oauthgomicrosoft

import (
    "fmt"

    "github.com/AlekSi/pointer"
    coreprov    "github.com/zekith/oauthgo/core/provider"
    provfactory "github.com/zekith/oauthgo/core/provider/factory"
    oidcprov    "github.com/zekith/oauthgo/core/provider/oauth2oidc"
    otypes      "github.com/zekith/oauthgo/core/types"
)

// buildMicrosoftDefaults builds the Microsoft provider config for a given tenant.
// tenant can be "common", "organizations", "consumers", or a specific tenant ID/domain.
func buildMicrosoftDefaults(tenant string) *otypes.OAuth2OIDCOptions {
    if tenant == "" { tenant = "common" }
    base := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0", tenant)

    return &otypes.OAuth2OIDCOptions{
        Name: pointer.ToString("microsoft"),
        Mode: pointer.To(otypes.OIDC),
        OAuth2: &otypes.OAuth2Options{
            AuthURL:  pointer.ToString(base + "/authorize"),
            TokenURL: pointer.ToString(base + "/token"),
            Scopes:   pointer.To([]string{"openid", "email", "profile", "offline_access"}),
            UsePKCE:  pointer.To(true),
        },
        OIDC: &otypes.OIDCOptions{
            Issuer:      pointer.ToString(fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)),
            JWKSURL:     pointer.ToString(fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenant)),
            UserInfoURL: pointer.ToString("https://graph.microsoft.com/oidc/userinfo"),
        },
    }
}

func init() {
    provfactory.MustRegister("microsoft", func() coreprov.Provider {
        return oidcprov.New(buildMicrosoftDefaults("common"))
    })
}
```

Notes:
- OAuth2‑only providers (e.g., GitHub) typically omit `OIDCOptions` and instead define a `UserInfoURL` against the REST API.
- Use `offline_access` (or provider‑specific flag) when you need refresh tokens; not all providers issue them for web apps.

---

## Security Checklist

- [ ] **HTTPS only** in production; never transmit auth cookies over plaintext.
- [ ] **Validate state and (if OIDC) nonce**; refuse callbacks with mismatches.
- [ ] **Enable PKCE** for public clients; many IdPs require it.
- [ ] **Restrict redirect URIs** to a strict allowlist; reject open redirects.
- [ ] **Set secure cookie flags**: `Secure`, `HttpOnly`, `SameSite=Lax/Strict`, and sensible `MaxAge`.
- [ ] **Scope minimally**; request only what you need.
- [ ] **Handle token revocation** (RFC 7009) for providers that support it.
- [ ] **Log & rate‑limit callbacks** to mitigate abuse.

---

## Troubleshooting & FAQ

**“Something went wrong” after consent**  
Ensure the callback URL you registered with the provider **exactly** matches the one your server exposes (scheme/host/port/path). Inspect state/nonce verification logs.

**“state parameter was modified”**  
The stored state doesn’t match the callback. Clear cookies, ensure a centralized session store (e.g., Redis) across instances, and verify that nothing overwrites the state between `/auth` and `/callback`.

**OIDC vs OAuth2‑only**  
If a provider doesn’t support OIDC (no ID token), set `Mode = OAuth2Only`. You can still fetch user profile data via the provider’s REST API when available.

**Refresh tokens**  
Some providers (e.g., LinkedIn, GitHub in certain flows) do **not** return refresh tokens for typical web apps. Use short‑lived access tokens plus re‑auth, or provider‑specific grants if you need long‑lived access.

---

## Development

```bash
# Run unit tests
go test ./...

# Static checks
go vet ./...
```

Project structure encourages adding providers under `/provider/...` and keeping protocol‑specific logic under `/core/...`.

---

## Roadmap

- Additional provider presets (Salesforce, Apple, Slack, Zoom, etc.)
- Example apps for popular HTTP routers (chi, gin, fiber)
- JWS/JWK utilities for custom token validation paths
- Convenience middleware for CSRF origin checking

---

## License

MIT — see [LICENSE](./LICENSE).
