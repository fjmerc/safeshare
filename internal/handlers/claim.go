package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/yourusername/safeshare/internal/config"
	"github.com/yourusername/safeshare/internal/database"
)

// ClaimHandler handles file download requests using claim codes
func ClaimHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/claim/{code}
		path := r.URL.Path
		prefix := "/api/claim/"
		if !strings.HasPrefix(path, prefix) {
			sendError(w, "Invalid claim URL", "INVALID_URL", http.StatusBadRequest)
			return
		}

		claimCode := strings.TrimPrefix(path, prefix)
		if claimCode == "" {
			sendError(w, "Claim code required", "NO_CLAIM_CODE", http.StatusBadRequest)
			return
		}

		// Get file record from database
		file, err := database.GetFileByClaimCode(db, claimCode)
		if err != nil {
			slog.Error("failed to get file by claim code", "claim_code", claimCode, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if file == nil {
			// File not found or expired
			sendError(w, "File not found or expired", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check download limit
		if file.MaxDownloads != nil && file.DownloadCount >= *file.MaxDownloads {
			sendError(w, "Download limit reached", "DOWNLOAD_LIMIT_REACHED", http.StatusGone)
			return
		}

		// Open the file
		filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)
		f, err := os.Open(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				slog.Error("file not found on disk", "path", filePath, "claim_code", claimCode)
				sendError(w, "File not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
			slog.Error("failed to open file", "path", filePath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		defer f.Close()

		// Get file info for size
		fileInfo, err := f.Stat()
		if err != nil {
			slog.Error("failed to stat file", "path", filePath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Increment download count
		if err := database.IncrementDownloadCount(db, file.ID); err != nil {
			slog.Error("failed to increment download count", "file_id", file.ID, "error", err)
			// Continue anyway - don't fail the download
		}

		// Set response headers
		w.Header().Set("Content-Type", file.MimeType)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.OriginalFilename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

		// Stream file to response
		written, err := io.Copy(w, f)
		if err != nil {
			slog.Error("failed to stream file", "path", filePath, "error", err)
			return
		}

		slog.Info("file downloaded",
			"claim_code", claimCode,
			"filename", file.OriginalFilename,
			"size", written,
			"download_count", file.DownloadCount+1,
		)
	}
}
