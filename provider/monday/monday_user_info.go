package oauthgomonday

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// User represents the complete set of user attributes available from Monday.com's "me" query
type User struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Email              string `json:"email"`
	IsAdmin            bool   `json:"is_admin"`
	IsGuest            bool   `json:"is_guest"`
	IsPending          bool   `json:"is_pending"`
	IsVerified         bool   `json:"is_verified"`
	IsViewOnly         bool   `json:"is_view_only"`
	Enabled            bool   `json:"enabled"`
	CreatedAt          string `json:"created_at"`
	JoinDate           string `json:"join_date"`
	CountryCode        string `json:"country_code"`
	Location           string `json:"location"`
	MobilePhone        string `json:"mobile_phone"`
	Phone              string `json:"phone"`
	Birthday           string `json:"birthday"`
	CurrentLanguage    string `json:"current_language"`
	PhotoOriginal      string `json:"photo_original"`
	PhotoSmall         string `json:"photo_small"`
	PhotoThumb         string `json:"photo_thumb"`
	PhotoThumbSmall    string `json:"photo_thumb_small"`
	PhotoTiny          string `json:"photo_tiny"`
	SignUpProductKind  string `json:"sign_up_product_kind"`
	TimeZoneIdentifier string `json:"time_zone_identifier"`
	UTCHoursDiff       int    `json:"utc_hours_diff"`
	URL                string `json:"url"`
}

// GraphQLRequest represents a Monday.com GraphQL request body
type GraphQLRequest struct {
	Query string `json:"query"`
}

// GraphQLResponse represents the response from Monday.com GraphQL API
type GraphQLResponse struct {
	Data struct {
		Me User `json:"me"`
	} `json:"data"`
	Errors []map[string]interface{} `json:"errors,omitempty"`
}

// GetMondayUserInfoHandler returns an http.HandlerFunc that extracts the access token
// from Authorization header and fetches extended user info from Monday.com
func GetMondayUserInfoHandler() http.HandlerFunc {
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

		// Send request to Monday.com
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
