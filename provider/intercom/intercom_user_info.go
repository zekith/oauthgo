package oauthgointercom

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// IntercomUser represents the extended response from Intercom's /me endpoint
type IntercomUser struct {
	Type          string `json:"type"`
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`

	App struct {
		Type                 string `json:"type"`
		IDCode               string `json:"id_code"`
		Name                 string `json:"name"`
		CreatedAt            int64  `json:"created_at"`
		Secure               bool   `json:"secure"`
		IdentityVerification bool   `json:"identity_verification"`
		Timezone             string `json:"timezone"`
		Region               string `json:"region"`
	} `json:"app"`

	Avatar struct {
		Type     string `json:"type"`
		ImageURL string `json:"image_url"`
	} `json:"avatar"`

	HasInboxSeat bool `json:"has_inbox_seat"`
}

// GetIntercomUserInfoHandler returns an http.HandlerFunc that fetches Intercom user info
func GetIntercomUserInfoHandler() http.HandlerFunc {
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

		var user IntercomUser
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode response: %v", err), http.StatusInternalServerError)
			return
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}
