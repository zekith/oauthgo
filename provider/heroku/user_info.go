package oauthgoheroku

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// GetUserInfo returns an http.HandlerFunc that fetches the authenticated Heroku user info
func GetUserInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract bearer token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")

		// Prepare request to Heroku API
		req, err := http.NewRequest("GET", "https://api.heroku.com/account", nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/vnd.heroku+json; version=3")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to send request: %v", err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("unexpected status from Heroku API: %s", resp.Status), resp.StatusCode)
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
