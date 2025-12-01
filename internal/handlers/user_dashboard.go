package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/utils"
)

// UserDashboardDataHandler returns dashboard data for the logged-in user
func UserDashboardDataHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Get user's files
		files, total, err := database.GetFilesByUserID(db, user.ID, limit, offset)
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
func UserDeleteFileHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Delete file (this will fail if file doesn't belong to user)
		file, err := database.DeleteFileByIDAndUserID(db, req.FileID, user.ID)
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
func UserRenameFileHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Update filename in database
		err := database.UpdateFileNameByIDAndUserID(db, req.FileID, user.ID, sanitizedFilename)
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
func UserEditExpirationHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Update expiration in database
		err = database.UpdateFileExpirationByIDAndUserID(db, req.FileID, user.ID, newExpiration)
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
func UserDeleteFileByClaimCodeHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Delete file (this will fail if file doesn't belong to user)
		file, err := database.DeleteFileByClaimCodeAndUserID(db, claimCode, user.ID)
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
func UserRenameFileByClaimCodeHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Update filename in database
		err := database.UpdateFileNameByClaimCodeAndUserID(db, claimCode, user.ID, sanitizedFilename)
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
func UserEditExpirationByClaimCodeHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Update expiration in database
		err := database.UpdateFileExpirationByClaimCodeAndUserID(db, claimCode, user.ID, newExpiration)
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
func UserRegenerateClaimCodeByClaimCodeHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Begin transaction with IMMEDIATE lock to prevent race conditions
		tx, err := database.BeginImmediateTx(db)
		if err != nil {
			slog.Error("failed to begin transaction", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Database error",
			})
			return
		}
		defer tx.Rollback() // Safe to call even after Commit()

		// Verify file exists and belongs to user
		var fileID int64
		var filename string
		err = tx.QueryRow(`
			SELECT id, original_filename
			FROM files
			WHERE claim_code = ? AND user_id = ?
		`, claimCode, user.ID).Scan(&fileID, &filename)

		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or access denied",
			})
			return
		} else if err != nil {
			slog.Error("database query failed",
				"error", err,
				"claim_code", claimCode,
				"user_id", user.ID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Database error",
			})
			return
		}

		// Generate new unique claim code with exponential backoff
		var newClaimCode string
		maxAttempts := 10
		for attempt := 0; attempt < maxAttempts; attempt++ {
			if attempt > 0 {
				backoff := time.Duration(10*(1<<uint(attempt-1))) * time.Millisecond
				time.Sleep(backoff)
			}

			code, err := utils.GenerateClaimCode()
			if err != nil {
				slog.Error("failed to generate claim code", "error", err)
				if attempt >= 2 {
					break
				}
				continue
			}

			// Check if code already exists
			var exists bool
			err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM files WHERE claim_code = ?)", code).Scan(&exists)
			if err != nil {
				slog.Error("failed to check claim code uniqueness", "error", err)
				continue
			}

			if !exists {
				newClaimCode = code
				break
			}
		}

		if newClaimCode == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Service temporarily unavailable. Please try again later.",
			})
			return
		}

		// Update database with new claim code
		result, err := tx.Exec(`
			UPDATE files
			SET claim_code = ?
			WHERE claim_code = ? AND user_id = ?
		`, newClaimCode, claimCode, user.ID)

		if err != nil {
			slog.Error("failed to update claim code", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to update claim code",
			})
			return
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil || rowsAffected == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or access denied",
			})
			return
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			slog.Error("failed to commit transaction", "error", err)
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
			"file_id", fileID,
			"filename", filename,
			"old_claim_code", claimCode,
			"new_claim_code", newClaimCode,
			"client_ip", clientIP,
		)

		// Build download URL
		downloadURL := buildDownloadURL(r, cfg, newClaimCode)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":      "Claim code regenerated successfully",
			"claim_code":   newClaimCode,
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
func UserRegenerateClaimCodeHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Begin transaction with IMMEDIATE lock to prevent race conditions.
		// Using BeginImmediateTx to acquire a RESERVED lock immediately,
		// which prevents SQLITE_BUSY errors from lock upgrade failures.
		tx, err := database.BeginImmediateTx(db)
		if err != nil {
			slog.Error("failed to begin transaction", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Database error",
			})
			return
		}
		defer tx.Rollback() // Safe to call even after Commit()

		// Verify file exists and belongs to user
		var currentClaimCode string
		var filename string
		err = tx.QueryRow(`
			SELECT claim_code, original_filename
			FROM files
			WHERE id = ? AND user_id = ?
		`, req.FileID, user.ID).Scan(&currentClaimCode, &filename)

		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or access denied",
			})
			return
		} else if err != nil {
			slog.Error("database query failed",
				"error", err,
				"file_id", req.FileID,
				"user_id", user.ID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Database error",
			})
			return
		}

		// Generate new unique claim code with exponential backoff
		var newClaimCode string
		maxAttempts := 10
		for attempt := 0; attempt < maxAttempts; attempt++ {
			// Add exponential backoff after first attempt
			if attempt > 0 {
				backoff := time.Duration(10*(1<<uint(attempt-1))) * time.Millisecond
				time.Sleep(backoff)
				slog.Debug("retrying claim code generation",
					"attempt", attempt,
					"backoff_ms", backoff.Milliseconds(),
				)
			}

			code, err := utils.GenerateClaimCode()
			if err != nil {
				slog.Error("failed to generate claim code", "error", err)
				// Abort after 3 crypto failures (indicates RNG failure)
				if attempt >= 2 {
					break
				}
				continue
			}

			// Check if code already exists (using transaction)
			var exists bool
			err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM files WHERE claim_code = ?)", code).Scan(&exists)
			if err != nil {
				slog.Error("failed to check claim code uniqueness", "error", err)
				continue
			}

			if !exists {
				newClaimCode = code
				break
			}

			// Log collision (extremely rare - possible attack indicator)
			slog.Warn("claim code collision detected",
				"attempt", attempt,
				"file_id", req.FileID,
			)
		}

		if newClaimCode == "" {
			slog.Error("failed to generate unique claim code after max attempts",
				"max_attempts", maxAttempts,
				"file_id", req.FileID,
				"user_id", user.ID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Service temporarily unavailable. Please try again later.",
			})
			return
		}

		// Update database with new claim code (with user_id check for security)
		result, err := tx.Exec(`
			UPDATE files
			SET claim_code = ?
			WHERE id = ? AND user_id = ?
		`, newClaimCode, req.FileID, user.ID)

		if err != nil {
			slog.Error("failed to update claim code",
				"error", err,
				"file_id", req.FileID,
				"old_claim_code", currentClaimCode,
				"new_claim_code", newClaimCode,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to update claim code",
			})
			return
		}

		// Verify row was actually updated (defense-in-depth)
		rowsAffected, err := result.RowsAffected()
		if err != nil || rowsAffected == 0 {
			// File ownership changed during operation or file deleted
			slog.Warn("claim code update affected 0 rows",
				"file_id", req.FileID,
				"user_id", user.ID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or access denied",
			})
			return
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			slog.Error("failed to commit transaction", "error", err)
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
			"filename", filename,
			"old_claim_code", currentClaimCode,
			"new_claim_code", newClaimCode,
			"client_ip", clientIP,
		)

		// Build download URL
		downloadURL := buildDownloadURL(r, cfg, newClaimCode)

		// Return success with new claim code and URL
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":      "Claim code regenerated successfully",
			"claim_code":   newClaimCode,
			"download_url": downloadURL,
		})
	}
}
