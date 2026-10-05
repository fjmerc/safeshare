package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/fjmerc/safeshare/internal/config"
)

// PublicConfigResponse contains public configuration settings safe to expose to clients
type PublicConfigResponse struct {
	Version                    string `json:"version"`
	RequireAuthForUpload       bool   `json:"require_auth_for_upload"`
	MaxFileSize                int64  `json:"max_file_size"`
	MaxExpirationHours         int    `json:"max_expiration_hours"`
	ChunkedUploadEnabled       bool   `json:"chunked_upload_enabled"`
	ChunkedUploadThreshold     int64  `json:"chunked_upload_threshold"`
	ChunkSize                  int64  `json:"chunk_size"`
	MalwareScanEnabled         bool   `json:"malware_scan_enabled"`         // ADR-015
	UnscannableUploadsRejected bool   `json:"unscannable_uploads_rejected"` // ADR-015: E2E/oversized uploads are rejected outright rather than accepted as "not_scanned"
	AnonymousMode              bool   `json:"anonymous_mode"`               // Ghost mode: no IPs/user agents/hashes recorded
	ClientEncryptionRequired   bool   `json:"client_encryption_required"`   // Uploads must be encrypted in the browser (REQUIRE_CLIENT_ENCRYPTION)
	StripMetadata              bool   `json:"strip_metadata"`               // Server strips metadata from supported file types
}

// PublicConfigHandler returns public configuration settings to the frontend
// This allows the frontend to dynamically adjust behavior based on server configuration
func PublicConfigHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		response := PublicConfigResponse{
			Version:                    Version,
			RequireAuthForUpload:       cfg.RequireAuthForUpload,
			MaxFileSize:                cfg.GetMaxFileSize(),
			MaxExpirationHours:         cfg.GetMaxExpirationHours(),
			ChunkedUploadEnabled:       cfg.ChunkedUploadEnabled,
			ChunkedUploadThreshold:     cfg.ChunkedUploadThreshold,
			ChunkSize:                  cfg.ChunkSize,
			MalwareScanEnabled:         cfg.Features.IsMalwareScanEnabled(),
			UnscannableUploadsRejected: cfg.Features.IsMalwareScanEnabled() && cfg.ClamAV.RejectUnscannable,
			AnonymousMode:              cfg.IsAnonymousMode(),
			ClientEncryptionRequired:   cfg.IsClientEncryptionRequired(),
			StripMetadata:              cfg.IsStripMetadata(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
