package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// UserDashboardDataHandler returns dashboard data for the logged-in user
func UserDashboardDataHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context (set by middleware)
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse pagination parameters
		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

		limit := 50 // default
		offset := 0

		if limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
				limit = l
			}
		}

		if offsetStr != "" {
			if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
				offset = o
			}
		}

		// Get user's files from repository
		files, total, err := repos.Users.GetFiles(ctx, user.ID, limit, offset)
		if err != nil {
			slog.Error("failed to get user files", "error", err, "user_id", user.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Build response with download URLs
		type FileResponse struct {
			ID                  int64     `json:"id"`
			ClaimCode           string    `json:"claim_code"`
			OriginalFilename    string    `json:"original_filename"`
			FileSize            int64     `json:"file_size"`
			MimeType            string    `json:"mime_type"`
			CreatedAt           time.Time `json:"created_at"`
			ExpiresAt           time.Time `json:"expires_at"`
			MaxDownloads        *int      `json:"max_downloads"`
			DownloadCount       int       `json:"download_count"`
			CompletedDownloads  int       `json:"completed_downloads"`
			DownloadURL         string    `json:"download_url"`
			IsExpired           bool      `json:"is_expired"`
			IsPasswordProtected bool      `json:"is_password_protected"`
		}

		fileResponses := make([]FileResponse, 0, len(files))
		for _, file := range files {
			fileResponses = append(fileResponses, FileResponse{
				ID:                  file.ID,
				ClaimCode:           file.ClaimCode,
				OriginalFilename:    file.OriginalFilename,
				FileSize:            file.FileSize,
				MimeType:            file.MimeType,
				CreatedAt:           file.CreatedAt,
				ExpiresAt:           file.ExpiresAt,
				MaxDownloads:        file.MaxDownloads,
				DownloadCount:       file.DownloadCount,
				CompletedDownloads:  file.CompletedDownloads,
				DownloadURL:         buildDownloadURL(r, cfg, file.ClaimCode),
				IsExpired:           time.Now().UTC().After(file.ExpiresAt) || (file.MaxDownloads != nil && *file.MaxDownloads > 0 && file.DownloadCount >= *file.MaxDownloads),
				IsPasswordProtected: file.PasswordHash != "",
			})
		}

		response := map[string]interface{}{
			"files":  fileResponses,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// UserDeleteFileHandler allows users to delete their own files
func UserDeleteFileHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse request
		var req struct {
			FileID int64 `json:"file_id"`
		}
		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		if req.FileID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid file ID",
			})
			return
		}

		// Delete file from repository (this will fail if file doesn't belong to user)
		file, err := repos.Users.DeleteFile(ctx, req.FileID, user.ID)
		if err != nil {
			slog.Warn("user file deletion failed",
				"user_id", user.ID,
				"file_id", req.FileID,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or does not belong to you",
			})
			return
		}

		// Validate stored filename (defense-in-depth against database corruption/compromise)
		if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
			slog.Error("stored filename validation failed",
				"filename", file.StoredFilename,
				"error", err,
				"user_id", user.ID,
				"client_ip", getClientIP(r),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Internal server error",
			})
			return
		}

		// Delete physical file
		filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			slog.Error("failed to delete physical file",
				"path", filePath,
				"error", err,
			)
			// Don't fail the request - database record is already deleted
		}

		// Decrypt if necessary before deletion (for cleanup)
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			slog.Debug("encrypted file deleted", "stored_filename", file.StoredFilename)
		}

		slog.Info("user deleted file",
			"user_id", user.ID,
			"username", user.Username,
			"file_id", file.ID,
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "File deleted successfully",
		})
	}
}

// UserRenameFileHandler allows users to rename their own files
func UserRenameFileHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		// Parse request
		var req struct {
			FileID      int64  `json:"file_id"`
			NewFilename string `json:"new_filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate file ID
		if req.FileID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid file ID",
			})
			return
		}

		// Validate and sanitize new filename
		if req.NewFilename == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Filename cannot be empty",
			})
			return
		}

		sanitizedFilename := utils.SanitizeFilename(req.NewFilename)
		if sanitizedFilename == "" || sanitizedFilename == "download" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid filename",
			})
			return
		}

		// Update filename in repository
		err := repos.Users.UpdateFileName(ctx, req.FileID, user.ID, sanitizedFilename)
		if err != nil {
			slog.Warn("user file rename failed",
				"user_id", user.ID,
				"file_id", req.FileID,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or does not belong to you",
			})
			return
		}

		slog.Info("user renamed file",
			"user_id", user.ID,
			"username", user.Username,
			"file_id", req.FileID,
			"old_filename", req.NewFilename,
			"new_filename", sanitizedFilename,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":      "File renamed successfully",
			"new_filename": sanitizedFilename,
		})
	}
}

// UserEditExpirationHandler allows users to edit the expiration date of their own files
func UserEditExpirationHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		// Parse request
		var req struct {
			FileID        int64  `json:"file_id"`
			NewExpiration string `json:"new_expiration"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate file ID
		if req.FileID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid file ID",
			})
			return
		}

		// Validate new expiration is not empty
		if req.NewExpiration == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Expiration date cannot be empty",
			})
			return
		}

		// Parse expiration timestamp (RFC3339 format)
		newExpiration, err := time.Parse(time.RFC3339, req.NewExpiration)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid date format",
			})
			return
		}

		// Check if this is "never expire" (year 9999)
		isNeverExpire := newExpiration.Year() == 9999

		// Validate expiration is in the future (skip for "never expire")
		if !isNeverExpire && newExpiration.Before(time.Now()) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Expiration date must be in the future",
			})
			return
		}

		// Validate expiration is within maximum allowed time (skip for "never expire")
		if !isNeverExpire {
			maxExpirationHours := cfg.GetMaxExpirationHours()
			maxExpiration := time.Now().Add(time.Duration(maxExpirationHours) * time.Hour)
			if newExpiration.After(maxExpiration) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Expiration cannot be more than %d hours from now", maxExpirationHours),
				})
				return
			}
		}

		// Update expiration in repository
		err = repos.Users.UpdateFileExpiration(ctx, req.FileID, user.ID, newExpiration)
		if err != nil {
			slog.Warn("user file expiration update failed",
				"user_id", user.ID,
				"file_id", req.FileID,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or does not belong to you",
			})
			return
		}

		slog.Info("user updated file expiration",
			"user_id", user.ID,
			"username", user.Username,
			"file_id", req.FileID,
			"new_expiration", newExpiration,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":        "File expiration updated successfully",
			"new_expiration": newExpiration.Format(time.RFC3339),
		})
	}
}

// UserDeleteFileByClaimCodeHandler allows users to delete their own files by claim code
// SDK endpoint: DELETE /api/user/files/{claimCode}
func UserDeleteFileByClaimCodeHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/user/files/{claimCode}
		claimCode := extractClaimCodeFromPath(r.URL.Path, "/api/user/files/")
		if err := utils.ValidateClaimCode(claimCode); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid claim code format",
			})
			return
		}

		// Delete file from repository (this will fail if file doesn't belong to user)
		file, err := repos.Users.DeleteFileByClaimCode(ctx, claimCode, user.ID)
		if err != nil {
			slog.Warn("user file deletion by claim code failed",
				"user_id", user.ID,
				"claim_code", claimCode,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or does not belong to you",
			})
			return
		}

		// Validate stored filename (defense-in-depth against database corruption/compromise)
		if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
			slog.Error("stored filename validation failed",
				"filename", file.StoredFilename,
				"error", err,
				"user_id", user.ID,
				"client_ip", getClientIP(r),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Internal server error",
			})
			return
		}

		// Delete physical file
		filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			slog.Error("failed to delete physical file",
				"path", filePath,
				"error", err,
			)
			// Don't fail the request - database record is already deleted
		}

		slog.Info("user deleted file by claim code",
			"user_id", user.ID,
			"username", user.Username,
			"file_id", file.ID,
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "File deleted successfully",
		})
	}
}

// UserRenameFileByClaimCodeHandler allows users to rename their files by claim code
// SDK endpoint: PUT /api/user/files/{claimCode}/rename
func UserRenameFileByClaimCodeHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/user/files/{claimCode}/rename
		claimCode := extractClaimCodeFromPathWithSuffix(r.URL.Path, "/api/user/files/", "/rename")
		if err := utils.ValidateClaimCode(claimCode); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid claim code format",
			})
			return
		}

		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		// Parse request - SDK sends {"filename": "new-name.txt"}
		var req struct {
			Filename string `json:"filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate and sanitize new filename
		if req.Filename == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Filename cannot be empty",
			})
			return
		}

		sanitizedFilename := utils.SanitizeFilename(req.Filename)
		if sanitizedFilename == "" || sanitizedFilename == "download" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid filename",
			})
			return
		}

		// Update filename in repository
		err := repos.Users.UpdateFileNameByClaimCode(ctx, claimCode, user.ID, sanitizedFilename)
		if err != nil {
			slog.Warn("user file rename by claim code failed",
				"user_id", user.ID,
				"claim_code", claimCode,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or does not belong to you",
			})
			return
		}

		slog.Info("user renamed file by claim code",
			"user_id", user.ID,
			"username", user.Username,
			"claim_code", claimCode,
			"new_filename", sanitizedFilename,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":      "File renamed successfully",
			"new_filename": sanitizedFilename,
		})
	}
}

// UserEditExpirationByClaimCodeHandler allows users to edit file expiration by claim code
// SDK endpoint: PUT /api/user/files/{claimCode}/expiration
func UserEditExpirationByClaimCodeHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/user/files/{claimCode}/expiration
		claimCode := extractClaimCodeFromPathWithSuffix(r.URL.Path, "/api/user/files/", "/expiration")
		if err := utils.ValidateClaimCode(claimCode); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid claim code format",
			})
			return
		}

		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		// Parse request - SDK sends {"expires_in_hours": 24}
		var req struct {
			ExpiresInHours *int `json:"expires_in_hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Calculate new expiration time
		var newExpiration time.Time
		if req.ExpiresInHours == nil {
			// No expiration ("never expire" - set to year 9999)
			newExpiration = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		} else if *req.ExpiresInHours <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Expiration hours must be positive or null for no expiration",
			})
			return
		} else {
			newExpiration = time.Now().Add(time.Duration(*req.ExpiresInHours) * time.Hour)
		}

		// Validate expiration is within maximum allowed time (skip for "never expire")
		isNeverExpire := newExpiration.Year() == 9999
		if !isNeverExpire {
			maxExpirationHours := cfg.GetMaxExpirationHours()
			maxExpiration := time.Now().Add(time.Duration(maxExpirationHours) * time.Hour)
			if newExpiration.After(maxExpiration) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": fmt.Sprintf("Expiration cannot be more than %d hours from now", maxExpirationHours),
				})
				return
			}
		}

		// Update expiration in repository
		err := repos.Users.UpdateFileExpirationByClaimCode(ctx, claimCode, user.ID, newExpiration)
		if err != nil {
			slog.Warn("user file expiration update by claim code failed",
				"user_id", user.ID,
				"claim_code", claimCode,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or does not belong to you",
			})
			return
		}

		slog.Info("user updated file expiration by claim code",
			"user_id", user.ID,
			"username", user.Username,
			"claim_code", claimCode,
			"new_expiration", newExpiration,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":        "File expiration updated successfully",
			"new_expiration": newExpiration.Format(time.RFC3339),
		})
	}
}

// UserRegenerateClaimCodeByClaimCodeHandler regenerates the claim code for a file identified by current claim code
// SDK endpoint: POST /api/user/files/{claimCode}/regenerate
func UserRegenerateClaimCodeByClaimCodeHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/user/files/{claimCode}/regenerate
		claimCode := extractClaimCodeFromPathWithSuffix(r.URL.Path, "/api/user/files/", "/regenerate")
		if err := utils.ValidateClaimCode(claimCode); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid claim code format",
			})
			return
		}

		// Get client IP for audit logging
		clientIP := getClientIP(r)

		// Regenerate claim code via repository
		result, err := repos.Users.RegenerateClaimCodeByClaimCode(ctx, claimCode, user.ID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "File not found or access denied",
				})
				return
			}
			if errors.Is(err, repository.ErrServiceUnavailable) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Service temporarily unavailable. Please try again later.",
				})
				return
			}
			slog.Error("failed to regenerate claim code",
				"error", err,
				"claim_code", claimCode,
				"user_id", user.ID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to update claim code",
			})
			return
		}

		slog.Info("claim code regenerated by claim code",
			"user_id", user.ID,
			"username", user.Username,
			"file_id", result.FileID,
			"filename", result.OriginalFilename,
			"old_claim_code", claimCode,
			"new_claim_code", result.NewClaimCode,
			"client_ip", clientIP,
		)

		// Build download URL
		downloadURL := buildDownloadURL(r, cfg, result.NewClaimCode)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":      "Claim code regenerated successfully",
			"claim_code":   result.NewClaimCode,
			"download_url": downloadURL,
		})
	}
}

// extractClaimCodeFromPath extracts the claim code from a URL path
// e.g., "/api/user/files/abc123" with prefix "/api/user/files/" returns "abc123"
func extractClaimCodeFromPath(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	claimCode := strings.TrimPrefix(path, prefix)
	// Remove any trailing slashes
	claimCode = strings.TrimSuffix(claimCode, "/")
	return claimCode
}

// extractClaimCodeFromPathWithSuffix extracts the claim code from a URL path with a suffix
// e.g., "/api/user/files/abc123/rename" with prefix "/api/user/files/" and suffix "/rename" returns "abc123"
func extractClaimCodeFromPathWithSuffix(path, prefix, suffix string) string {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	claimCode := strings.TrimPrefix(path, prefix)
	claimCode = strings.TrimSuffix(claimCode, suffix)
	return claimCode
}

// UserRegenerateClaimCodeHandler regenerates the claim code for a user's file
func UserRegenerateClaimCodeHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		// Parse request
		var req struct {
			FileID int64 `json:"file_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate file ID
		if req.FileID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid file ID",
			})
			return
		}

		// Get client IP for audit logging
		clientIP := getClientIP(r)

		// Regenerate claim code via repository
		result, err := repos.Users.RegenerateClaimCode(ctx, req.FileID, user.ID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "File not found or access denied",
				})
				return
			}
			if errors.Is(err, repository.ErrServiceUnavailable) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Service temporarily unavailable. Please try again later.",
				})
				return
			}
			slog.Error("failed to regenerate claim code",
				"error", err,
				"file_id", req.FileID,
				"user_id", user.ID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to update claim code",
			})
			return
		}

		// Audit log the regeneration
		slog.Info("claim code regenerated",
			"user_id", user.ID,
			"username", user.Username,
			"file_id", req.FileID,
			"filename", result.OriginalFilename,
			"old_claim_code", result.OldClaimCode,
			"new_claim_code", result.NewClaimCode,
			"client_ip", clientIP,
		)

		// Build download URL
		downloadURL := buildDownloadURL(r, cfg, result.NewClaimCode)

		// Return success with new claim code and URL
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":      "Claim code regenerated successfully",
			"claim_code":   result.NewClaimCode,
			"download_url": downloadURL,
		})
	}
}
