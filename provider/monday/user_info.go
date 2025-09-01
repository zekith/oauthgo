package oauthgomonday

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// GraphQLRequest represents a Monday.com GraphQL request body
type GraphQLRequest struct {
	Query string `json:"query"`
}

// GraphQLResponse represents the response from Monday.com GraphQL API
type GraphQLResponse struct {
	Data struct {
		Me map[string]interface{} `json:"me"`
	} `json:"data"`
	Errors []map[string]interface{} `json:"errors,omitempty"`
}

// GetUserInfo returns an http.HandlerFunc that extracts the access token
// from the Authorization header and fetches extended user info from Monday.com
func GetUserInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}
		accessToken := strings.TrimPrefix(authHeader, "Bearer ")

		// Extended GraphQL query for all fields
		query := GraphQLRequest{
			Query: `
			{
				me {
					id
					name
					email
					is_admin
					is_guest
					is_pending
					is_verified
					is_view_only
					enabled
					created_at
					join_date
					country_code
					location
					mobile_phone
					phone
					birthday
					current_language
					photo_original
					photo_small
					photo_thumb
					photo_thumb_small
					photo_tiny
					sign_up_product_kind
					time_zone_identifier
					utc_hours_diff
					url
				}
			}`,
		}
		body, _ := json.Marshal(query)

		// Send a request to Monday.com
		req, err := http.NewRequest("POST", "https://api.monday.com/v2", bytes.NewBuffer(body))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create request: %v", err), http.StatusInternalServerError)
			return
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
			http.Error(w, fmt.Sprintf("unexpected status from Monday.com: %s", resp.Status), resp.StatusCode)
			return
		}

		var gqlResp GraphQLResponse
		if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode response: %v", err), http.StatusInternalServerError)
			return
		}
		if len(gqlResp.Errors) > 0 {
			http.Error(w, fmt.Sprintf("monday.com returned errors: %+v", gqlResp.Errors), http.StatusBadGateway)
			return
		}

		// Return user info as JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(gqlResp.Data.Me)
	}
}
