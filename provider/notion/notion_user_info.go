package oauthgonotion

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// NotionResponse represents the full API response
type NotionResponse struct {
	Object string `json:"object"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Person *struct {
		Email string `json:"email"`
	} `json:"person,omitempty"`
	Bot *struct {
		Owner struct {
			Type string `json:"type"`
			User *struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"user,omitempty"`
			Workspace bool `json:"workspace,omitempty"`
		} `json:"owner"`
	} `json:"bot,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

// GetNotionUserInfoHandler returns an http.HandlerFunc that extracts the access token
// from the Authorization header and fetches user info from Notion (/v1/users/me).
func GetNotionUserInfoHandler(notionVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")

		// Create a request to Notion API
		req, err := http.NewRequest("GET", "https://api.notion.com/v1/users/me", nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
			return
		}
		if notionVersion != "" {
			req.Header.Set("Notion-Version", notionVersion)
		} else {
			req.Header.Set("Notion-Version", "2022-06-28")
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to send request: %v", err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("unexpected status from Notion: %s", resp.Status), resp.StatusCode)
			return
		}

		var notionResp NotionResponse
		if err := json.NewDecoder(resp.Body).Decode(&notionResp); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode response: %v", err), http.StatusInternalServerError)
			return
		}

		// Return user info as JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(notionResp)
	}
}
