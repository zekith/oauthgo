# oauthgo — Extensible OAuth2 / OIDC library for Go

Clean core + provider modules (Google, Microsoft, Apple, LinkedIn, Salesforce) with PKCE, HMAC-signed state, and normalized profile.

## Layout

```
oauthgo/
  core/        # PKCE, state/nonce, helpers, optional HTTP handlers
  provider/    # Provider interface + implementations
examples/
  server/      # Minimal web server wiring
```

## Quick start

1) Edit env in `examples/server/.env.example` and copy to `.env`.
2) Run:

```bash
cd examples/server
go run .
```

Visit:

- `http://localhost:8080/auth/google`
- `http://localhost:8080/auth/microsoft`
- `http://localhost:8080/auth/salesforce`
- `http://localhost:8080/auth/linkedin`
- `http://localhost:8080/auth/apple` (optional; requires Apple keys)

Callbacks land at `/callback/{provider}`.

> This is a starter. Read comments marked `TODO:` where provider policies vary (e.g., LinkedIn refresh tokens, Apple name-first-login).

## Security defaults

- PKCE (S256) for all providers that support it.
- HMAC-signed, time-limited state with nonce + redirect echo.
- One interface for all IdPs; OIDC ID tokens verified via JWKS for OIDC providers.
- Apple ES256 client secret generated per exchange with short TTL.

## Multi-tenant note

Wire a resolver that picks client credentials by tenant (domain/org). See `examples/server/main.go` for a simple pattern.


## Replay store (Redis vs in-memory)

By default, the example server uses in-memory anti-replay. To use Redis, set:

```
REDIS_ADDR=127.0.0.1:6379
REDIS_PASSWORD=
REDIS_DB=0
```

Library types:

- `core.ReplayProtector` — interface
- `core.NewMemoryReplayProtector()` — in-process store
- `core.NewRedisReplayProtector(client, prefix)` — shared store using `SET NX EX`


## CI & Quality

- GitHub Actions workflow: `.github/workflows/ci.yml`
  - Lint via `golangci-lint`
  - Unit tests (with a Redis service for Redis-backed store tests)
  - Cross-platform build on Ubuntu/macOS/Windows, Go 1.22 & 1.23

## Local Redis

Use Docker Compose to run Redis locally:

```bash
docker compose up -d redis
go test ./...
```

Or stop it with:

```bash
docker compose down
```

## Make targets

- `make tidy` — `go mod tidy`
- `make lint` — `golangci-lint run`
- `make test` — `go test -race -v ./...`
- `make up` / `make down` — start/stop Redis via Compose


## Cookie auth (demo)

The example server sets a signed session cookie `oauthgo_session` after callback. View it at `/me` and clear it via `/logout`.
Configure with env:

- `SESSION_COOKIE` (default: `oauthgo_session`)
- `SESSION_SECRET` (HMAC key; set to a strong secret in prod)

## Token revocation (RFC 7009)

A helper `core.RevokeToken` is provided. OIDC providers auto-discover `revocation_endpoint` (if published) and `provider.Revoke()` will call it.
- Apple uses its own endpoint (`/auth/revoke`) with the Apple client secret.
- LinkedIn currently returns `core.ErrRevocationUnsupported`.

Example endpoint (demo only):
```
GET /revoke/{provider}?token={access_or_refresh_token}
```
