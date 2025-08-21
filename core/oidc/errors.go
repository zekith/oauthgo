package oauthgooidc

import "errors"

// Errors related to OAuth2/OIDC providers.
// These errors are used to indicate specific conditions that may arise
// during the OAuth2/OIDC flow, such as unsupported features or errors
// encountered during token handling.
var (
	ErrRevocationUnsupported = errors.New("token revocation not supported by this provider")
	ErrRefreshNotSupported   = errors.New("refresh token not supported by this provider")
)
