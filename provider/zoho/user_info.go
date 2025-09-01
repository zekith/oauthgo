package oauthgozoho

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// GetUserInfo returns an http.HandlerFunc that extracts the access token
// from the Authorization header and fetches user info from Zoho Accounts
func GetUserInfo(domain string) http.HandlerFunc {
	if domain == "" {
		domain = "accounts.zoho.com" // default to US
	}

	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")

		// Build Zoho UserInfo URL
		url := fmt.Sprintf("https://%s/oauth/user/info", domain)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Authorization", "Zoho-oauthtoken "+accessToken)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to call Zoho API: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("Zoho API returned %s", resp.Status), resp.StatusCode)
			return
		}

		user := make(map[string]interface{})
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode Zoho response: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}
