package oauthgohubspot

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// GetUserInfo returns an http.HandlerFunc that
// extracts the Bearer token from the Authorization header,
// calls HubSpot's `/oauth/v1/access-tokens/{token}` endpoint,
// and returns user/account info.
func GetUserInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")

		// Call HubSpot user info API
		url := fmt.Sprintf("https://api.hubapi.com/oauth/v1/access-tokens/%s", accessToken)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to call HubSpot API: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("HubSpot API returned %s", resp.Status), resp.StatusCode)
			return
		}

		userResp := make(map[string]interface{})
		if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode HubSpot response: %v", err), http.StatusInternalServerError)
			return
		}

		// Return normalized JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userResp)
	}
}
