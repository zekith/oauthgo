package oauthgoapple

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AppleUserResponse wraps the decoded ID Token claims for Apple users
type AppleUserResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Nonce         string `json:"nonce,omitempty"`
	AuthTime      int64  `json:"auth_time,omitempty"`
}

// GetUserInfo extracts and decodes Apple id_token
// from the Authorization header (Bearer id_token) and returns user info.
func GetUserInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		var idToken string
		fmt.Sscanf(authHeader, "Bearer %s", &idToken)
		if idToken == "" {
			http.Error(w, "invalid Authorization header", http.StatusUnauthorized)
			return
		}

		// Decode id_token
		claims, err := ParseIDToken(idToken)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to decode id_token: %v", err), http.StatusBadRequest)
			return
		}

		// Wrap into response
		resp := AppleUserResponse{
			Sub:           claims.Subject,
			Email:         claims.Email,
			EmailVerified: claims.EmailVerified,
			Nonce:         claims.Nonce,
			AuthTime:      claims.AuthTime,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
