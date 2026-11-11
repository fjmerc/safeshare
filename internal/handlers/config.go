package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/fjmerc/safeshare/internal/config"
)

// legacyReportedChunkSize is what /api/config reports as chunk_size now that
// CHUNK_SIZE is retired: the old default, for clients that still read it.
const legacyReportedChunkSize = 10 * 1024 * 1024

// PublicConfigResponse contains public configuration settings safe to expose to clients
type PublicConfigResponse struct {
	Version                string `json:"version"`
	RequireAuthForUpload   bool   `json:"require_auth_for_upload"`
	MaxFileSize            int64  `json:"max_file_size"`
	MaxExpirationHours     int    `json:"max_expiration_hours"`
	ChunkedUploadEnabled   bool   `json:"chunked_upload_enabled"`
	ChunkedUploadThreshold int64  `json:"chunked_upload_threshold"`
	// Deprecated: always 10 MiB. Chunk size is chosen per upload (5, 10 or
	// 20 MiB by file size) and returned by /api/upload/init; CHUNK_SIZE is
	// retired. Kept so existing clients that read it don't break.
	ChunkSize                  int64 `json:"chunk_size"`
	MalwareScanEnabled         bool  `json:"malware_scan_enabled"`         // ADR-015
	UnscannableUploadsRejected bool  `json:"unscannable_uploads_rejected"` // ADR-015: E2E/oversized uploads are rejected outright rather than accepted as "not_scanned"
	AnonymousMode              bool  `json:"anonymous_mode"`               // Ghost mode: no IPs/user agents/hashes recorded
	ClientEncryptionRequired   bool  `json:"client_encryption_required"`   // Uploads must be encrypted in the browser (REQUIRE_CLIENT_ENCRYPTION)
	StripMetadata              bool  `json:"strip_metadata"`               // Server strips metadata from supported file types
	DropEnabled                bool  `json:"drop_enabled"`                 // No-JavaScript drop page at /drop (DROP_RECIPIENT)
	MaxFilesPerBundle          int   `json:"max_files_per_bundle"`         // Most files one bundle (one link for several files) may hold
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
			MaxFilesPerBundle:          cfg.GetMaxFilesPerBundle(),
			ChunkSize:                  legacyReportedChunkSize,
			MalwareScanEnabled:         cfg.Features.IsMalwareScanEnabled(),
			UnscannableUploadsRejected: cfg.Features.IsMalwareScanEnabled() && cfg.ClamAV.RejectUnscannable,
			AnonymousMode:              cfg.IsAnonymousMode(),
			ClientEncryptionRequired:   cfg.IsClientEncryptionRequired(),
			StripMetadata:              cfg.IsStripMetadata(),
			DropEnabled:                cfg.Drop.Enabled(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
