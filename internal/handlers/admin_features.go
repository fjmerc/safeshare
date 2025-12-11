package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// featureFlagsRequest represents the JSON request body for updating feature flags.
type featureFlagsRequest struct {
	EnablePostgreSQL  *bool `json:"enable_postgresql,omitempty"`
	EnableS3Storage   *bool `json:"enable_s3_storage,omitempty"`
	EnableSSO         *bool `json:"enable_sso,omitempty"`
	EnableMFA         *bool `json:"enable_mfa,omitempty"`
	EnableWebhooks    *bool `json:"enable_webhooks,omitempty"`
	EnableAPITokens   *bool `json:"enable_api_tokens,omitempty"`
	EnableMalwareScan *bool `json:"enable_malware_scan,omitempty"`
	EnableBackups     *bool `json:"enable_backups,omitempty"`
}

// AdminGetFeatureFlagsHandler returns the current state of all feature flags.
// GET /api/admin/features
func AdminGetFeatureFlagsHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get in-memory feature flags from config
		flags := cfg.Features.GetAll()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"feature_flags": flags,
		})
	}
}

// AdminUpdateFeatureFlagsHandler updates feature flags.
// PUT /api/admin/features
//
// Accepts a JSON body with any subset of feature flags to update.
// Only provided fields are updated; omitted fields retain their current values.
// Updates are persisted to the database and applied to the in-memory config.
func AdminUpdateFeatureFlagsHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()
		clientIP := getClientIP(r)

		// Limit request body size
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64KB limit

		var req featureFlagsRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields() // Reject unknown fields for strict validation
		if err := decoder.Decode(&req); err != nil {
			slog.Error("failed to parse feature flags request", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Invalid request format",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		// Get current flags from database (or defaults)
		currentFlags, err := repos.Settings.GetFeatureFlags(ctx)
		if err != nil {
			slog.Error("failed to get current feature flags", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Failed to retrieve current feature flags",
				"code":  "DATABASE_ERROR",
			})
			return
		}

		// Apply updates only for provided fields (partial update)
		if req.EnablePostgreSQL != nil {
			currentFlags.EnablePostgreSQL = *req.EnablePostgreSQL
		}
		if req.EnableS3Storage != nil {
			currentFlags.EnableS3Storage = *req.EnableS3Storage
		}
		if req.EnableSSO != nil {
			currentFlags.EnableSSO = *req.EnableSSO
		}
		if req.EnableMFA != nil {
			currentFlags.EnableMFA = *req.EnableMFA
		}
		if req.EnableWebhooks != nil {
			currentFlags.EnableWebhooks = *req.EnableWebhooks
		}
		if req.EnableAPITokens != nil {
			currentFlags.EnableAPITokens = *req.EnableAPITokens
		}
		if req.EnableMalwareScan != nil {
			currentFlags.EnableMalwareScan = *req.EnableMalwareScan
		}
		if req.EnableBackups != nil {
			currentFlags.EnableBackups = *req.EnableBackups
		}

		// Persist to database
		if err := repos.Settings.UpdateFeatureFlags(ctx, currentFlags); err != nil {
			slog.Error("failed to update feature flags in database", "error", err, "ip", clientIP)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "Failed to save feature flags",
				"code":  "DATABASE_ERROR",
			})
			return
		}

		// Update in-memory config
		cfg.Features.SetAll(config.FeatureFlagsData{
			EnablePostgreSQL:  currentFlags.EnablePostgreSQL,
			EnableS3Storage:   currentFlags.EnableS3Storage,
			EnableSSO:         currentFlags.EnableSSO,
			EnableMFA:         currentFlags.EnableMFA,
			EnableWebhooks:    currentFlags.EnableWebhooks,
			EnableAPITokens:   currentFlags.EnableAPITokens,
			EnableMalwareScan: currentFlags.EnableMalwareScan,
			EnableBackups:     currentFlags.EnableBackups,
		})

		// Sync MFA and SSO enabled state with their config structs
		// This ensures existing code that checks cfg.MFA.Enabled continues to work
		if req.EnableMFA != nil {
			cfg.SetMFAEnabled(currentFlags.EnableMFA)
		}
		if req.EnableSSO != nil {
			cfg.SetSSOEnabled(currentFlags.EnableSSO)
		}

		slog.Info("feature flags updated",
			"ip", clientIP,
			"postgresql", currentFlags.EnablePostgreSQL,
			"s3_storage", currentFlags.EnableS3Storage,
			"sso", currentFlags.EnableSSO,
			"mfa", currentFlags.EnableMFA,
			"webhooks", currentFlags.EnableWebhooks,
			"api_tokens", currentFlags.EnableAPITokens,
			"malware_scan", currentFlags.EnableMalwareScan,
			"backups", currentFlags.EnableBackups,
		)

		// Return updated flags
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":       true,
			"feature_flags": cfg.Features.GetAll(),
		})
	}
}
