package authogodeps

import (
	"sync"

	oauthgocookie "github.com/zekith/oauthgo/core/cookie"
	oauthgoreplay "github.com/zekith/oauthgo/core/replay"
	oauthgostore "github.com/zekith/oauthgo/core/store"
)

// OAuthGoDeps represents the dependencies for the OAuthGo library used across the library.
// These dependencies are initialized by the application and are used by the library globally.
type OAuthGoDeps struct {
	ReplayProtector      oauthgoreplay.ReplayProtector
	SessionStore         oauthgostore.SessionStore
	SessionCookieManager oauthgocookie.SessionCookieManager
}

var (
	oAuthGoDeps *OAuthGoDeps
	once        sync.Once
)

// Init initializes the oauthgo global dependencies.
func Init(deps *OAuthGoDeps) {
	once.Do(func() {
		oAuthGoDeps = deps
	})
}

// Get returns the oauthgo global dependencies.
func Get() *OAuthGoDeps {
	if oAuthGoDeps == nil {
		panic("authogodeps.Init() must be called before Get()")
	}
	return oAuthGoDeps
}
