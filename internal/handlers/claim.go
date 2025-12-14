package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// ClaimHandler handles file download requests using claim codes
func ClaimHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// Only accept GET requests
		if r.Method != http.MethodGet {
			sendErrorResponse(w, r, "Method Not Allowed", "This endpoint only accepts GET requests.", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/claim/{code}
		path := r.URL.Path
		prefix := "/api/claim/"
		if !strings.HasPrefix(path, prefix) {
			sendErrorResponse(w, r, "Invalid URL", "The claim URL format is invalid. Please check the link and try again.", "INVALID_URL", http.StatusBadRequest)
			return
		}

		claimCode := strings.TrimPrefix(path, prefix)
		if claimCode == "" {
			sendErrorResponse(w, r, "Missing Claim Code", "No claim code was provided. Please check the link and try again.", "NO_CLAIM_CODE", http.StatusBadRequest)
			return
		}

		// Get file record from database
		file, err := repos.Files.GetByClaimCode(ctx, claimCode)
		if err != nil {
			slog.Error("failed to get file by claim code", "claim_code", redactClaimCode(claimCode), "error", err)
			sendErrorResponse(w, r, "Server Error", "An internal error occurred while retrieving the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if file == nil {
			// File not found or expired
			slog.Warn("file access denied",
				"reason", "not_found_or_expired",
				"claim_code", redactClaimCode(claimCode),
				"client_ip", getClientIP(r),
			)
			sendErrorResponse(w, r, "File Not Found or Expired", "This file does not exist or has expired. Files on SafeShare are automatically deleted after their expiration time. Please contact the sender if you need the file again.", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check password if file is password-protected
		if utils.IsPasswordProtected(file.PasswordHash) {
			providedPassword := r.URL.Query().Get("password")
			if !utils.VerifyPassword(file.PasswordHash, providedPassword) {
				// Record metrics
				metrics.DownloadsTotal.WithLabelValues("password_failed").Inc()

				slog.Warn("file access denied",
					"reason", "incorrect_password",
					"claim_code", redactClaimCode(claimCode),
					"filename", file.OriginalFilename,
					"client_ip", getClientIP(r),
					"user_agent", getUserAgent(r),
				)
				sendErrorResponse(w, r, "Incorrect Password", "The password provided for this file is incorrect. Please check the password and try again, or contact the sender for the correct password.", "INCORRECT_PASSWORD", http.StatusUnauthorized)
				return
			}
		}

		// Note: Download limit check moved to atomic TryIncrementDownloadWithLimit() to prevent race conditions (P1 fix)

		// Validate stored filename (defense-in-depth against database corruption/compromise)
		if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
			slog.Error("stored filename validation failed",
				"filename", file.StoredFilename,
				"error", err,
				"claim_code", redactClaimCode(claimCode),
				"client_ip", getClientIP(r),
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Read file from disk
		filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)

		// Store original claim code for optimistic locking
		originalClaimCode := file.ClaimCode

		// Atomically increment download count with limit check (P1 fix)
		// This prevents race conditions where multiple downloads could exceed max_downloads
		success, err := repos.Files.TryIncrementDownloadWithLimit(ctx, file.ID, originalClaimCode)
		if err != nil {
			// Check if claim code changed during download
			if errors.Is(err, repository.ErrClaimCodeChanged) {
				slog.Warn("claim code changed during download",
					"file_id", file.ID,
					"original_code", redactClaimCode(originalClaimCode),
					"client_ip", getClientIP(r),
				)
				// Continue with download - file retrieval already succeeded
				// But don't increment counter since claim code is now invalid
			} else {
				slog.Error("failed to increment download count", "file_id", file.ID, "error", err)
				// Continue anyway - don't fail the download
			}
		} else if !success {
			// Download limit reached (atomic check)
			// Note: We do NOT emit a webhook here because the file.expired webhook
			// was already sent when the last successful download completed.
			// This path handles subsequent rejected requests after the limit was reached.
			slog.Warn("file access denied",
				"reason", "download_limit_reached",
				"claim_code", redactClaimCode(claimCode),
				"filename", file.OriginalFilename,
				"client_ip", getClientIP(r),
			)

			sendErrorResponse(w, r, "Download Limit Reached", "This file has reached its maximum number of downloads and is no longer available. Please contact the sender if you need the file again.", "DOWNLOAD_LIMIT_REACHED", http.StatusGone)
			return
		}

		// Serve file with Range support (handles both full and partial downloads)
		serveFileWithRangeSupport(w, r, file, filePath, cfg, repos)

		// Calculate remaining downloads for logging
		var remainingDownloads string
		newDownloadCount := file.DownloadCount + 1
		if file.MaxDownloads != nil {
			remaining := *file.MaxDownloads - newDownloadCount
			remainingDownloads = fmt.Sprintf("%d", remaining)

			// Check if this download caused the file to reach its limit
			// Emit file.expired webhook when the last allowed download completes
			if remaining == 0 {
				reason := "download_limit_reached"
				EmitWebhookEvent(&webhooks.Event{
					Type:      webhooks.EventFileExpired,
					Timestamp: time.Now(),
					File: webhooks.FileData{
						ClaimCode: claimCode,
						Filename:  file.OriginalFilename,
						Size:      file.FileSize,
						MimeType:  file.MimeType,
						ExpiresAt: file.ExpiresAt,
						Reason:    &reason,
					},
				})
				slog.Info("file expired due to download limit",
					"claim_code", redactClaimCode(claimCode),
					"filename", file.OriginalFilename,
					"max_downloads", *file.MaxDownloads,
				)
			}
		} else {
			remainingDownloads = "unlimited"
		}

		slog.Debug("download completed",
			"claim_code", redactClaimCode(claimCode),
			"download_count", newDownloadCount,
			"remaining_downloads", remainingDownloads,
		)
	}
}

// ClaimInfoHandler returns file information without downloading
func ClaimInfoHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
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
		file, err := repos.Files.GetByClaimCode(ctx, claimCode)
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
		if file.MaxDownloads != nil && *file.MaxDownloads > 0 && file.DownloadCount >= *file.MaxDownloads {
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
			"completed_downloads":    file.CompletedDownloads,
			"download_limit_reached": downloadLimitReached,
			"password_required":      utils.IsPasswordProtected(file.PasswordHash),
			"download_url":           downloadURL,
			"sha256_hash":            file.SHA256Hash, // SHA256 checksum for client verification
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
