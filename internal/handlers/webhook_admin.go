package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// ListWebhookConfigsHandler lists all webhook configurations
func ListWebhookConfigsHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		configs, err := database.GetAllWebhookConfigs(db)
		if err != nil {
		slog.Error("failed to get webhook configs", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
		"error": "Failed to retrieve webhook configurations",
		})
		return
		}

		// Mask service tokens in response for security
		for _, config := range configs {
		if config.ServiceToken != "" {
			config.ServiceToken = utils.MaskToken(config.ServiceToken)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configs)
	}
}

// CreateWebhookConfigHandler creates a new webhook configuration
func CreateWebhookConfigHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
		URL            string   `json:"url"`
		Secret         string   `json:"secret"`
		ServiceToken   string   `json:"service_token,omitempty"`
		Enabled        bool     `json:"enabled"`
		Events         []string `json:"events"`
		Format         string   `json:"format"`
		MaxRetries     int      `json:"max_retries"`
		TimeoutSeconds int      `json:"timeout_seconds"`
	}

		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse create webhook request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate required fields
		if req.URL == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "URL is required",
			})
			return
		}

		// Validate URL format and scheme
		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid URL format",
			})
			return
		}

		// Only allow HTTP and HTTPS schemes to prevent SSRF
		scheme := strings.ToLower(parsedURL.Scheme)
		if scheme != "http" && scheme != "https" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Only HTTP and HTTPS URLs are allowed",
			})
			return
		}

		// Validate hostname is present
		if parsedURL.Host == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "URL must include a hostname",
			})
			return
		}

		if req.Secret == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Secret is required",
			})
			return
		}

		if len(req.Events) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "At least one event type is required",
			})
			return
		}

		// Validate format if provided
		if req.Format != "" && !webhooks.ValidateFormat(req.Format) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid webhook format. Supported formats: safeshare, gotify, ntfy, discord",
			})
			return
		}

		// Validate service token length (Gotify/ntfy tokens are typically 20-50 chars)
		if len(req.ServiceToken) > 512 {
		w.Header().Set("Content-Type", "application/json")
		 w.WriteHeader(http.StatusBadRequest)
		 json.NewEncoder(w).Encode(map[string]string{
		 "error": "Service token exceeds maximum length of 512 characters",
		 })
		 return
		}

	// Set defaults
	if req.Format == "" {
		req.Format = "safeshare"
	}
	if req.MaxRetries == 0 {
		req.MaxRetries = 5
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 30
	}

		config := &webhooks.Config{
		URL:            req.URL,
		Secret:         req.Secret,
		ServiceToken:   req.ServiceToken,
		Enabled:        req.Enabled,
		Events:         req.Events,
		Format:         webhooks.WebhookFormat(req.Format),
		MaxRetries:     req.MaxRetries,
		 TimeoutSeconds: req.TimeoutSeconds,
	}

		if err := database.CreateWebhookConfig(db, config); err != nil {
			slog.Error("failed to create webhook config", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to create webhook configuration",
			})
			return
		}

		slog.Info("webhook config created", "id", config.ID, "url", config.URL)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(config)
	}
}

// UpdateWebhookConfigHandler updates an existing webhook configuration
func UpdateWebhookConfigHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get ID from query parameter
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Webhook ID is required",
			})
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid webhook ID",
			})
			return
		}

		var req struct {
		URL            string   `json:"url"`
		Secret         string   `json:"secret"`
		ServiceToken   string   `json:"service_token,omitempty"`
		Enabled        bool     `json:"enabled"`
		Events         []string `json:"events"`
		Format         string   `json:"format"`
		MaxRetries     int      `json:"max_retries"`
		 TimeoutSeconds int      `json:"timeout_seconds"`
	}

		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse update webhook request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate required fields
		if req.URL == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "URL is required",
			})
			return
		}

		// Validate URL format and scheme
		parsedURL, err := url.Parse(req.URL)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid URL format",
			})
			return
		}

		// Only allow HTTP and HTTPS schemes to prevent SSRF
		scheme := strings.ToLower(parsedURL.Scheme)
		if scheme != "http" && scheme != "https" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Only HTTP and HTTPS URLs are allowed",
			})
			return
		}

		// Validate hostname is present
		if parsedURL.Host == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "URL must include a hostname",
			})
			return
		}

		if req.Secret == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Secret is required",
			})
			return
		}

		if len(req.Events) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "At least one event type is required",
			})
			return
		}

		// Validate format if provided
		if req.Format != "" && !webhooks.ValidateFormat(req.Format) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid webhook format. Supported formats: safeshare, gotify, ntfy, discord",
			})
			return
		}

		// Validate service token length (Gotify/ntfy tokens are typically 20-50 chars)
		if len(req.ServiceToken) > 512 {
		w.Header().Set("Content-Type", "application/json")
		 w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
		  "error": "Service token exceeds maximum length of 512 characters",
		})
		return
	}

	// Set default format if not provided
	if req.Format == "" {
		req.Format = "safeshare"
	}

	config := &webhooks.Config{
		ID:             id,
		URL:            req.URL,
		Secret:         req.Secret,
		ServiceToken:   req.ServiceToken,
		Enabled:        req.Enabled,
		Events:         req.Events,
		Format:         webhooks.WebhookFormat(req.Format),
		MaxRetries:     req.MaxRetries,
		 TimeoutSeconds: req.TimeoutSeconds,
	}

		if err := database.UpdateWebhookConfig(db, config); err != nil {
			slog.Error("failed to update webhook config", "id", id, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to update webhook configuration",
			})
			return
		}

		slog.Info("webhook config updated", "id", config.ID, "url", config.URL)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	}
}

// DeleteWebhookConfigHandler deletes a webhook configuration
func DeleteWebhookConfigHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get ID from query parameter
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Webhook ID is required",
			})
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid webhook ID",
			})
			return
		}

		if err := database.DeleteWebhookConfig(db, id); err != nil {
			slog.Error("failed to delete webhook config", "id", id, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to delete webhook configuration",
			})
			return
		}

		slog.Info("webhook config deleted", "id", id)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Webhook configuration deleted successfully",
		})
	}
}

// TestWebhookConfigHandler sends a test webhook payload
func TestWebhookConfigHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get ID from query parameter
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Webhook ID is required",
			})
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid webhook ID",
			})
			return
		}

		// Get webhook config
		config, err := database.GetWebhookConfig(db, id)
		if err != nil {
			slog.Error("failed to get webhook config for test", "id", id, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Webhook configuration not found",
			})
			return
		}

		// Create test event
		testEvent := &webhooks.Event{
			Type:      webhooks.EventFileUploaded,
			Timestamp: time.Now(),
			File: webhooks.FileData{
				ClaimCode: "TEST123",
				Filename:  "test-file.txt",
				Size:      1024,
				MimeType:  "text/plain",
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
		}

		// Transform payload according to webhook format
		payload, err := webhooks.TransformPayload(testEvent, config.Format)
		if err != nil {
			slog.Error("failed to create test payload", "error", err, "format", config.Format)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to create test payload",
			})
			return
		}

		// Deliver test webhook with config (supports service tokens)
		result := webhooks.DeliverWebhookWithConfig(config, config.URL, config.Secret, payload, config.TimeoutSeconds)

		response := map[string]interface{}{
			"success":       result.Success,
			"response_code": result.ResponseCode,
			"response_body": result.ResponseBody,
		}

		if result.Error != nil {
			response["error"] = result.Error.Error()
		}

		slog.Info("test webhook sent", "id", id, "url", config.URL, "success", result.Success)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// ListWebhookDeliveriesHandler lists webhook delivery history with pagination
func ListWebhookDeliveriesHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse pagination parameters
		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

		limit := 50 // default
		offset := 0 // default

		if limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
				limit = l
			}
		}

		if offsetStr != "" {
			if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
				offset = o
			}
		}

		deliveries, err := database.GetWebhookDeliveries(db, limit, offset)
		if err != nil {
			slog.Error("failed to get webhook deliveries", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to retrieve webhook deliveries",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(deliveries)
	}
}

// GetWebhookDeliveryHandler retrieves a single webhook delivery
func GetWebhookDeliveryHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get ID from query parameter
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Delivery ID is required",
			})
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid delivery ID",
			})
			return
		}

		delivery, err := database.GetWebhookDelivery(db, id)
		if err != nil {
			slog.Error("failed to get webhook delivery", "id", id, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Webhook delivery not found",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(delivery)
	}
}
