package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/fjmerc/safeshare/internal/config"
)

// PublicConfigResponse contains public configuration settings safe to expose to clients
type PublicConfigResponse struct {
	Version                string `json:"version"`
	RequireAuthForUpload   bool   `json:"require_auth_for_upload"`
	MaxFileSize            int64  `json:"max_file_size"`
	ChunkedUploadEnabled   bool   `json:"chunked_upload_enabled"`
	ChunkedUploadThreshold int64  `json:"chunked_upload_threshold"`
	ChunkSize              int64  `json:"chunk_size"`
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
			Version:                Version,
			RequireAuthForUpload:   cfg.RequireAuthForUpload,
			MaxFileSize:            cfg.GetMaxFileSize(),
			ChunkedUploadEnabled:   cfg.ChunkedUploadEnabled,
			ChunkedUploadThreshold: cfg.ChunkedUploadThreshold,
			ChunkSize:              cfg.ChunkSize,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
