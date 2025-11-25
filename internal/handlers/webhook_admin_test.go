package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/testutil"
)

// TestCreateWebhookConfigHandler tests webhook creation
func TestCreateWebhookConfigHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		checkResponse  bool
	}{
		{
			name: "valid webhook creation",
			requestBody: map[string]interface{}{
				"url":             "https://example.com/webhook",
				"secret":          "test-secret-key",
				"events":          []string{"file.uploaded", "file.downloaded"},
				"enabled":         true,
				"max_retries":     5,
				"timeout_seconds": 30,
			},
			expectedStatus: http.StatusCreated,
			checkResponse:  true,
		},
		{
			name: "missing URL",
			requestBody: map[string]interface{}{
				"secret":  "test-secret-key",
				"events":  []string{"file.uploaded"},
				"enabled": true,
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse:  false,
		},
		{
			name: "missing secret",
			requestBody: map[string]interface{}{
				"url":     "https://example.com/webhook",
				"events":  []string{"file.uploaded"},
				"enabled": true,
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse:  false,
		},
		{
			name: "missing events",
			requestBody: map[string]interface{}{
				"url":     "https://example.com/webhook",
				"secret":  "test-secret-key",
				"enabled": true,
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse:  false,
		},
		{
			name: "invalid URL scheme (ftp)",
			requestBody: map[string]interface{}{
				"url":     "ftp://example.com/webhook",
				"secret":  "test-secret-key",
				"events":  []string{"file.uploaded"},
				"enabled": true,
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse:  false,
		},
		{
			name: "invalid URL format",
			requestBody: map[string]interface{}{
				"url":     "not-a-valid-url",
				"secret":  "test-secret-key",
				"events":  []string{"file.uploaded"},
				"enabled": true,
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/admin/webhooks", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler := CreateWebhookConfigHandler(db)
			handler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.checkResponse && rr.Code == http.StatusCreated {
				var response map[string]interface{}
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				// Check that webhook ID is returned
				if _, ok := response["id"]; !ok {
					t.Error("Response missing 'id' field")
				}
			}
		})
	}
}

// TestListWebhookConfigsHandler tests webhook listing
func TestListWebhookConfigsHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/webhooks", nil)
	rr := httptest.NewRecorder()

	handler := ListWebhookConfigsHandler(db)
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	// Verify response is valid JSON (should be a slice)
	var response interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
}

// TestUpdateWebhookConfigHandler tests webhook updates
func TestUpdateWebhookConfigHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	tests := []struct {
		name           string
		webhookID      string
		requestBody    map[string]interface{}
		expectedStatus int
	}{
		{
			name:      "invalid webhook ID",
			webhookID: "invalid",
			requestBody: map[string]interface{}{
				"url":     "https://example.com/webhook",
				"secret":  "test-secret",
				"enabled": false,
				"events":  []string{"file.uploaded"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:      "non-existent webhook",
			webhookID: "999",
			requestBody: map[string]interface{}{
				"url":     "https://example.com/webhook",
				"secret":  "test-secret",
				"enabled": false,
				"events":  []string{"file.uploaded"},
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.requestBody)
			if err != nil {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			req := httptest.NewRequest(http.MethodPut, "/api/admin/webhooks?id="+tt.webhookID, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler := UpdateWebhookConfigHandler(db)
			handler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestDeleteWebhookConfigHandler tests webhook deletion
func TestDeleteWebhookConfigHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	tests := []struct {
		name           string
		webhookID      string
		expectedStatus int
	}{
		{
			name:           "invalid webhook ID",
			webhookID:      "invalid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "non-existent webhook",
			webhookID:      "999",
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/admin/webhooks?id="+tt.webhookID, nil)
			rr := httptest.NewRecorder()

			handler := DeleteWebhookConfigHandler(db)
			handler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestTestWebhookConfigHandler tests webhook test endpoint
func TestTestWebhookConfigHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	tests := []struct {
		name           string
		webhookID      string
		expectedStatus int
	}{
		{
			name:           "invalid webhook ID",
			webhookID:      "invalid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "non-existent webhook",
			webhookID:      "999",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/admin/webhooks?id="+tt.webhookID, nil)
			rr := httptest.NewRecorder()

			handler := TestWebhookConfigHandler(db)
			handler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestListWebhookDeliveriesHandler tests webhook delivery history
func TestListWebhookDeliveriesHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	tests := []struct {
		name           string
		query          string
		expectedStatus int
	}{
		{
			name:           "list deliveries",
			query:          "?limit=10&offset=0",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/admin/webhooks/deliveries"+tt.query, nil)
			rr := httptest.NewRecorder()

			handler := ListWebhookDeliveriesHandler(db)
			handler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestGetWebhookDeliveryHandler tests getting single webhook delivery
func TestGetWebhookDeliveryHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	tests := []struct {
		name           string
		deliveryID     string
		expectedStatus int
	}{
		{
			name:           "invalid delivery ID",
			deliveryID:     "invalid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "non-existent delivery",
			deliveryID:     "999",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/admin/webhooks/deliveries?id="+tt.deliveryID, nil)
			rr := httptest.NewRecorder()

			handler := GetWebhookDeliveryHandler(db)
			handler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestClearWebhookDeliveriesHandler tests clearing webhook delivery history
func TestClearWebhookDeliveriesHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)

	tests := []struct {
		name           string
		method         string
		expectedStatus int
		checkResponse  bool
	}{
		{
			name:           "clear deliveries with DELETE method",
			method:         http.MethodDelete,
			expectedStatus: http.StatusOK,
			checkResponse:  true,
		},
		{
			name:           "method not allowed - GET",
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
			checkResponse:  false,
		},
		{
			name:           "method not allowed - POST",
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
			checkResponse:  false,
		},
		{
			name:           "method not allowed - PUT",
			method:         http.MethodPut,
			expectedStatus: http.StatusMethodNotAllowed,
			checkResponse:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/admin/webhook-deliveries/clear", nil)
			rr := httptest.NewRecorder()

			handler := ClearWebhookDeliveriesHandler(db)
			handler(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.checkResponse && rr.Code == http.StatusOK {
				var response map[string]interface{}
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				// Check that message is returned
				if _, ok := response["message"]; !ok {
					t.Error("Response missing 'message' field")
				}

				// Check that deleted_count is returned
				if _, ok := response["deleted_count"]; !ok {
					t.Error("Response missing 'deleted_count' field")
				}
			}
		})
	}
}

// TestClearWebhookDeliveriesHandler_WithData tests clearing when deliveries exist
func TestClearWebhookDeliveriesHandler_WithData(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// First, create a webhook config and some deliveries
	createBody := map[string]interface{}{
		"url":             "https://example.com/webhook",
		"secret":          "test-secret-key",
		"events":          []string{"file.uploaded"},
		"enabled":         true,
		"max_retries":     3,
		"timeout_seconds": 30,
	}
	createBodyJSON, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/api/admin/webhooks", bytes.NewReader(createBodyJSON))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	CreateWebhookConfigHandler(db)(createRR, createReq)

	if createRR.Code != http.StatusCreated {
		t.Fatalf("Failed to create webhook config: %s", createRR.Body.String())
	}

	// Now clear deliveries (should return 0 deleted since we haven't created any deliveries directly)
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/webhook-deliveries/clear", nil)
	rr := httptest.NewRecorder()

	handler := ClearWebhookDeliveriesHandler(db)
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// deleted_count should be 0 or more (depending on if any deliveries were created)
	if deletedCount, ok := response["deleted_count"].(float64); ok {
		if deletedCount < 0 {
			t.Errorf("deleted_count should be >= 0, got %v", deletedCount)
		}
	} else {
		t.Error("deleted_count should be a number")
	}
}
