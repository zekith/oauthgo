package oauthgobootstrap

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/pborman/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/zekith/oauthgo/core/cookie"
	"github.com/zekith/oauthgo/core/replay"
	"github.com/zekith/oauthgo/core/state"
	"github.com/zekith/oauthgo/core/store"
)

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const (
	EnvStateHMAC        = "STATE_HMAC"
	EnvRedisAddr        = "REDIS_ADDR"
	EnvRedisPassword    = "REDIS_PASSWORD"
	EnvRedisDB          = "REDIS_DB"
	EnvSessionRedisAddr = "SESSION_REDIS_ADDR"
	EnvSessionRedisPass = "SESSION_REDIS_PASSWORD"
	EnvSessionRedisDB   = "SESSION_REDIS_DB"
	EnvSessionCookie    = "SESSION_COOKIE"
	EnvSessionSecret    = "SESSION_SECRET"

	RedisReplayPrefix  = "oauthgo:state:"
	RedisSessionPrefix = "oauthgo:sess:"

	DefaultSessionCookie = "oauthgo_session"

	StateCodecTTL    = 10 * time.Minute
	HTTPClientTTL    = 15 * time.Second
	SessionCookieTTL = 24 * time.Hour
)

// -----------------------------------------------------------------------------
// Core wiring
// -----------------------------------------------------------------------------

// Core holds reusable, app-agnostic wiring.
type Core struct {
	StateCodec      *oauthgostate.StateCodec
	HTTPClient      *http.Client
	ReplayProtector oauthgoreplay.ReplayProtector
	SessionStore    oauthgostore.SessionStore
	CookieMgr       *oauthgocookie.CookieSessionManager
}

func BuildCore() *Core {
	return &Core{
		StateCodec:      StateCodec(),
		HTTPClient:      HTTPClient(),
		ReplayProtector: ReplayProtector(),
		SessionStore:    SessionStore(),
		CookieMgr:       CookieManager(),
	}
}

// -----------------------------------------------------------------------------
// Builders
// -----------------------------------------------------------------------------

// StateCodec returns an HMAC+TTL state codec (reads: STATE_HMAC, auto generated id).
func StateCodec() *oauthgostate.StateCodec {
	secret := env(EnvStateHMAC, uuid.NewUUID().String())
	return &oauthgostate.StateCodec{HMACSecret: []byte(secret), TTL: StateCodecTTL}
}

// HTTPClient returns an HTTP client with sane timeout.
func HTTPClient() *http.Client { return &http.Client{Timeout: HTTPClientTTL} }

// ReplayProtector prefers Redis when REDIS_ADDR is present, else memory.
func ReplayProtector() oauthgoreplay.ReplayProtector {
	if addr := os.Getenv(EnvRedisAddr); addr != "" {
		rc := redisClient(addr, EnvRedisPassword, EnvRedisDB)
		log.Printf("replay store: redis %s", addr)
		return oauthgoreplay.NewRedisReplayProtector(rc, RedisReplayPrefix)
	}
	log.Printf("replay store: in-memory")
	return oauthgoreplay.NewMemoryReplayProtector()
}

// SessionStore prefers SESSION_REDIS_* then falls back to REDIS_* then in-memory.
func SessionStore() oauthgostore.SessionStore {
	if addr := os.Getenv(EnvSessionRedisAddr); addr != "" {
		rc := redisClient(addr, EnvSessionRedisPass, EnvSessionRedisDB)
		log.Printf("session store: redis %s", addr)
		return oauthgostore.NewRedisSessionStore(rc, RedisSessionPrefix)
	}
	if addr := os.Getenv(EnvRedisAddr); addr != "" {
		rc := redisClient(addr, EnvRedisPassword, EnvRedisDB)
		log.Printf("session store: redis %s (from REDIS_ADDR)", addr)
		return oauthgostore.NewRedisSessionStore(rc, RedisSessionPrefix)
	}
	log.Printf("session store: in-memory")
	return oauthgostore.NewMemorySessionStore()
}

// CookieManager returns HMAC-authenticated session cookie manager.
func CookieManager() *oauthgocookie.CookieSessionManager {
	return &oauthgocookie.CookieSessionManager{
		Name:   env(EnvSessionCookie, DefaultSessionCookie),
		Secret: []byte(env(EnvSessionSecret, uuid.NewUUID().String())),
		TTL:    SessionCookieTTL,
		Secure: false,
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func redisClient(addr, passwordEnv, dbEnv string) *redis.Client {
	opt := &redis.Options{Addr: addr}
	if pw := os.Getenv(passwordEnv); pw != "" {
		opt.Password = pw
	}
	if dbs := os.Getenv(dbEnv); dbs != "" {
		if n, err := strconv.Atoi(dbs); err == nil {
			opt.DB = n
		}
	}
	return redis.NewClient(opt)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
