package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/yourusername/safeshare/internal/config"
	"github.com/yourusername/safeshare/internal/database"
	"github.com/yourusername/safeshare/internal/utils"
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
			slog.Error("failed to get file by claim code", "claim_code", redactClaimCode(claimCode), "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if file == nil {
			// File not found or expired
			slog.Warn("file access denied",
				"reason", "not_found_or_expired",
				"claim_code", redactClaimCode(claimCode),
				"client_ip", getClientIP(r),
			)
			sendError(w, "File not found or expired", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check password if file is password-protected
		if utils.IsPasswordProtected(file.PasswordHash) {
			providedPassword := r.URL.Query().Get("password")
			if !utils.VerifyPassword(file.PasswordHash, providedPassword) {
				slog.Warn("file access denied",
					"reason", "incorrect_password",
					"claim_code", redactClaimCode(claimCode),
					"filename", file.OriginalFilename,
					"client_ip", getClientIP(r),
					"user_agent", getUserAgent(r),
				)
				sendError(w, "Incorrect password", "INCORRECT_PASSWORD", http.StatusUnauthorized)
				return
			}
		}

		// Check download limit
		if file.MaxDownloads != nil && file.DownloadCount >= *file.MaxDownloads {
			slog.Warn("file access denied",
				"reason", "download_limit_reached",
				"claim_code", redactClaimCode(claimCode),
				"filename", file.OriginalFilename,
				"download_count", file.DownloadCount,
				"max_downloads", *file.MaxDownloads,
				"client_ip", getClientIP(r),
			)
			sendError(w, "Download limit reached", "DOWNLOAD_LIMIT_REACHED", http.StatusGone)
			return
		}

		// Read file from disk
		filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				slog.Error("file not found on disk", "path", filePath, "claim_code", redactClaimCode(claimCode))
				sendError(w, "File not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
			slog.Error("failed to read file", "path", filePath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Decrypt if file appears to be encrypted and encryption is enabled
		var dataToServe []byte
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) && utils.IsEncrypted(fileData) {
			decrypted, err := utils.DecryptFile(fileData, cfg.EncryptionKey)
			if err != nil {
				slog.Error("failed to decrypt file", "claim_code", redactClaimCode(claimCode), "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			dataToServe = decrypted
			slog.Debug("file decrypted", "encrypted_size", len(fileData), "decrypted_size", len(decrypted))
		} else {
			// File is not encrypted or encryption not enabled
			dataToServe = fileData
		}

		// Increment download count
		if err := database.IncrementDownloadCount(db, file.ID); err != nil {
			slog.Error("failed to increment download count", "file_id", file.ID, "error", err)
			// Continue anyway - don't fail the download
		}

		// Set response headers
		w.Header().Set("Content-Type", file.MimeType)
		// Sanitize filename to prevent header injection attacks
		safeFilename := utils.SanitizeForContentDisposition(file.OriginalFilename)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, safeFilename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(dataToServe)))

		// Write file to response
		written, err := w.Write(dataToServe)
		if err != nil {
			slog.Error("failed to write file to response", "claim_code", redactClaimCode(claimCode), "error", err)
			return
		}

		// Calculate remaining downloads
		var remainingDownloads string
		if file.MaxDownloads != nil {
			remaining := *file.MaxDownloads - (file.DownloadCount + 1)
			remainingDownloads = fmt.Sprintf("%d", remaining)
		} else {
			remainingDownloads = "unlimited"
		}

		slog.Info("file downloaded",
			"claim_code", redactClaimCode(claimCode),
			"filename", file.OriginalFilename,
			"size", written,
			"download_count", file.DownloadCount+1,
			"remaining_downloads", remainingDownloads,
			"client_ip", getClientIP(r),
			"user_agent", getUserAgent(r),
		)
	}
}

// ClaimInfoHandler returns file information without downloading
func ClaimInfoHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/claim/{code}/info
		path := r.URL.Path
		prefix := "/api/claim/"
		suffix := "/info"

		if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
			sendError(w, "Invalid claim URL", "INVALID_URL", http.StatusBadRequest)
			return
		}

		// Remove prefix and suffix to get claim code
		claimCode := strings.TrimPrefix(path, prefix)
		claimCode = strings.TrimSuffix(claimCode, suffix)

		if claimCode == "" {
			sendError(w, "Claim code required", "NO_CLAIM_CODE", http.StatusBadRequest)
			return
		}

		// Get file record from database
		file, err := database.GetFileByClaimCode(db, claimCode)
		if err != nil {
			slog.Error("failed to get file by claim code", "claim_code", redactClaimCode(claimCode), "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if file == nil {
			// File not found or expired
			sendError(w, "File not found or expired", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check download limit
		downloadLimitReached := false
		if file.MaxDownloads != nil && file.DownloadCount >= *file.MaxDownloads {
			downloadLimitReached = true
		}

		// Build download URL
		downloadURL := buildDownloadURL(r, cfg, claimCode)

		// Return file info as JSON
		response := map[string]interface{}{
			"claim_code":             file.ClaimCode,
			"original_filename":      file.OriginalFilename,
			"file_size":              file.FileSize,
			"mime_type":              file.MimeType,
			"created_at":             file.CreatedAt,
			"expires_at":             file.ExpiresAt,
			"max_downloads":          file.MaxDownloads,
			"download_count":         file.DownloadCount,
			"download_limit_reached": downloadLimitReached,
			"password_required":      utils.IsPasswordProtected(file.PasswordHash),
			"download_url":           downloadURL,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

		slog.Info("file info retrieved",
			"claim_code", redactClaimCode(claimCode),
			"filename", file.OriginalFilename,
		)
	}
}
