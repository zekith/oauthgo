package oauthgointercom

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// GetUserInfo returns an http.HandlerFunc that fetches Intercom user info
func GetUserInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")

		// Build request to Intercom /me endpoint
		req, err := http.NewRequest("GET", "https://api.intercom.io/me", nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/json") // REQUIRED for Intercom

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to send request: %v", err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("unexpected status from Intercom: %s", resp.Status), resp.StatusCode)
			return
		}

		user := make(map[string]interface{})
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode response: %v", err), http.StatusInternalServerError)
			return
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}
