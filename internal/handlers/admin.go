package handlers

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// AdminLoginHandler handles admin login
func AdminLoginHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request (supports both JSON and form-encoded)
		var username, password string

		contentType := r.Header.Get("Content-Type")
		if contentType == "application/json" {
			var loginReq struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			// Limit JSON request body size to prevent memory exhaustion
			r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

			if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
				slog.Error("failed to parse JSON login request", "error", err)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Invalid request format",
				})
				return
			}
			username = loginReq.Username
			password = loginReq.Password
		} else {
			// Parse as form data
			if err := r.ParseForm(); err != nil {
				slog.Error("failed to parse form login request", "error", err)
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			username = r.FormValue("username")
			password = r.FormValue("password")
		}

		clientIP := getClientIP(r)
		userAgent := getUserAgent(r)

		// Track authentication method and user (if applicable)
		var authenticatedUser *models.User
		isAdminCredentials := false

		// Try validating against admin_credentials table first
		valid, err := database.ValidateAdminCredentials(db, username, password)
		if err == nil && valid {
			isAdminCredentials = true
		} else {
			// Try to get user from users table with admin role
			user, userErr := database.GetUserByUsername(db, username)

			// Check if user exists, password matches, has admin role, and is active
			if userErr == nil && user != nil &&
				utils.VerifyPassword(user.PasswordHash, password) &&
				user.Role == "admin" &&
				user.IsActive {
				// User authenticated successfully with admin role
				authenticatedUser = user
				slog.Info("admin login successful via users table",
					"username", username,
					"user_id", user.ID,
					"ip", clientIP,
				)
			}
		}

		// If both authentication methods failed
		if !isAdminCredentials && authenticatedUser == nil {
			slog.Warn("admin login failed - invalid credentials",
				"username", username,
				"ip", clientIP,
			)

			// Return error with slight delay to prevent timing attacks
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid username or password",
			})
			return
		}

		// Generate session token
		sessionToken, err := utils.GenerateSessionToken()
		if err != nil {
			slog.Error("failed to generate session token", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Calculate expiry time
		expiresAt := time.Now().Add(time.Duration(cfg.SessionExpiryHours) * time.Hour)

		// Create appropriate session type based on authentication method
		if isAdminCredentials {
			// Legacy admin_credentials path: create admin_session
			err = database.CreateSession(db, sessionToken, expiresAt, clientIP, userAgent)
			if err != nil {
				slog.Error("failed to create admin session", "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Set admin session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "admin_session",
				Value:    sessionToken,
				Path:     "/admin",
				HttpOnly: true,
				Secure:   cfg.HTTPSEnabled,
				SameSite: http.SameSiteStrictMode,
				Expires:  expiresAt,
			})

			// Generate and set CSRF token
			csrfToken, err := middleware.SetCSRFCookie(w, cfg)
			if err != nil {
				slog.Error("failed to set CSRF cookie", "error", err)
			}

			slog.Info("admin login successful via admin_credentials",
				"username", username,
				"ip", clientIP,
				"user_agent", userAgent,
			)

			// Return success response with CSRF token
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":    true,
				"csrf_token": csrfToken,
			})
		} else {
			// Users table path: create user_session for better compatibility
			err = database.CreateUserSession(db, authenticatedUser.ID, sessionToken, expiresAt, clientIP, userAgent)
			if err != nil {
				slog.Error("failed to create user session", "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Update last login timestamp
			if err := database.UpdateUserLastLogin(db, authenticatedUser.ID); err != nil {
				slog.Error("failed to update last login", "error", err)
				// Don't fail the request, just log
			}

			// Set user session cookie (site-wide path for access to /dashboard)
			http.SetCookie(w, &http.Cookie{
				Name:     "user_session",
				Value:    sessionToken,
				Path:     "/",
				HttpOnly: true,
				Secure:   cfg.HTTPSEnabled,
				SameSite: http.SameSiteStrictMode,
				Expires:  expiresAt,
			})

			// Generate and set CSRF token
			csrfToken, err := middleware.SetCSRFCookie(w, cfg)
			if err != nil {
				slog.Error("failed to set CSRF cookie", "error", err)
			}

			// Return user info response (similar to UserLoginHandler)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":                 true,
				"csrf_token":              csrfToken,
				"id":                      authenticatedUser.ID,
				"username":                authenticatedUser.Username,
				"email":                   authenticatedUser.Email,
				"role":                    authenticatedUser.Role,
				"require_password_change": authenticatedUser.RequirePasswordChange,
			})
		}
	}
}

// AdminLogoutHandler handles admin logout
func AdminLogoutHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check for admin_session cookie (legacy admin_credentials login)
		adminCookie, adminErr := r.Cookie("admin_session")
		if adminErr == nil {
			// Delete admin session from database
			database.DeleteSession(db, adminCookie.Value)

			slog.Info("admin logout via admin_session",
				"ip", getClientIP(r),
			)
		}

		// Check for user_session cookie (users table with admin role)
		userCookie, userErr := r.Cookie("user_session")
		if userErr == nil {
			// Delete user session from database
			database.DeleteUserSession(db, userCookie.Value)

			slog.Info("admin logout via user_session",
				"ip", getClientIP(r),
			)
		}

		// Clear admin_session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_session",
			Value:    "",
			Path:     "/admin",
			HttpOnly: true,
			Secure:   cfg.HTTPSEnabled,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1, // Delete cookie
		})

		// Clear user_session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "user_session",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.HTTPSEnabled,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1, // Delete cookie
		})

		// Clear CSRF cookie for /admin path
		http.SetCookie(w, &http.Cookie{
			Name:   "csrf_token",
			Value:  "",
			Path:   "/admin",
			MaxAge: -1,
		})

		// Clear CSRF cookie for / path
		http.SetCookie(w, &http.Cookie{
			Name:   "csrf_token",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{
			"success": true,
		})
	}
}

// AdminDashboardDataHandler returns dashboard data (files, stats)
func AdminDashboardDataHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse pagination parameters
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		// P2 security fix: Add upper limit to prevent integer overflow and full table scans
		if page > 1000000 {
			page = 1000000
		}

		pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		if pageSize < 1 || pageSize > 100 {
			pageSize = 20
		}

		searchTerm := r.URL.Query().Get("search")

		// Calculate offset with validation to prevent overflow
		offset := (page - 1) * pageSize
		// Sanity check: if offset is negative (overflow), cap it
		if offset < 0 {
			offset = 0
			page = 1
		}

		// Get files
		var files []models.File
		var total int
		var err error

		if searchTerm != "" {
			files, total, err = database.SearchFilesForAdmin(db, searchTerm, pageSize, offset)
		} else {
			files, total, err = database.GetAllFilesForAdmin(db, pageSize, offset)
		}

		if err != nil {
			slog.Error("failed to get files for admin", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get storage stats
		totalFiles, storageUsed, err := database.GetStats(db, cfg.UploadDir)
		if err != nil {
			slog.Error("failed to get storage stats", "error", err)
			// Continue with partial data
		}

		// Get blocked IPs
		blockedIPs, err := database.GetBlockedIPs(db)
		if err != nil {
			slog.Error("failed to get blocked IPs", "error", err)
			blockedIPs = []database.BlockedIP{}
		}

		// Get partial uploads metrics
		partialUploadsSize, err := utils.GetPartialUploadsSize(cfg.UploadDir)
		if err != nil {
			slog.Error("failed to get partial uploads size", "error", err)
			partialUploadsSize = 0
		}

		// Calculate quota usage (includes both completed files and partial uploads)
		var quotaLimitBytes int64
		var quotaUsedPercent float64
		totalStorageUsed := storageUsed + partialUploadsSize
		if cfg.GetQuotaLimitGB() > 0 {
			quotaLimitBytes = cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024
			if quotaLimitBytes > 0 {
				quotaUsedPercent = (float64(totalStorageUsed) / float64(quotaLimitBytes)) * 100
			}
		}

		partialUploadsCount, err := database.GetIncompletePartialUploadsCount(db)
		if err != nil {
			slog.Error("failed to get partial uploads count", "error", err)
			partialUploadsCount = 0
		}

		// Prepare response with file details
		type FileResponse struct {
			ID                 int64     `json:"id"`
			ClaimCode          string    `json:"claim_code"`
			OriginalFilename   string    `json:"original_filename"`
			FileSize           int64     `json:"file_size"`
			MimeType           string    `json:"mime_type"`
			CreatedAt          time.Time `json:"created_at"`
			ExpiresAt          time.Time `json:"expires_at"`
			MaxDownloads       *int      `json:"max_downloads"`
			DownloadCount      int       `json:"download_count"`
			CompletedDownloads int       `json:"completed_downloads"`
			Username           *string   `json:"username"` // nullable - nil for anonymous uploads
			UploaderIP         string    `json:"uploader_ip"`
			PasswordProtected  bool      `json:"password_protected"`
		}

		fileResponses := make([]FileResponse, len(files))
		for i, file := range files {
			fileResponses[i] = FileResponse{
				ID:                 file.ID,
				ClaimCode:          file.ClaimCode,
				OriginalFilename:   file.OriginalFilename,
				FileSize:           file.FileSize,
				MimeType:           file.MimeType,
				CreatedAt:          file.CreatedAt,
				ExpiresAt:          file.ExpiresAt,
				MaxDownloads:       file.MaxDownloads,
				DownloadCount:      file.DownloadCount,
				CompletedDownloads: file.CompletedDownloads,
				Username:           file.Username,
				UploaderIP:         file.UploaderIP,
				PasswordProtected:  file.PasswordHash != "",
			}
		}

		response := map[string]interface{}{
			"files": fileResponses,
			"pagination": map[string]interface{}{
				"page":        page,
				"page_size":   pageSize,
				"total":       total,
				"total_pages": (total + pageSize - 1) / pageSize,
			},
			"stats": map[string]interface{}{
				"total_files":           totalFiles,
				"storage_used_bytes":    storageUsed,
				"quota_limit_bytes":     quotaLimitBytes,
				"quota_used_percent":    quotaUsedPercent,
				"partial_uploads_bytes": partialUploadsSize,
				"partial_uploads_count": partialUploadsCount,
			},
			"blocked_ips": blockedIPs,
			"system_info": map[string]interface{}{
				"db_path":     cfg.DBPath,
				"upload_dir":  cfg.UploadDir,
				"partial_dir": filepath.Join(cfg.UploadDir, ".partial"),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// AdminDeleteFileHandler deletes a file
func AdminDeleteFileHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get claim code from URL or form
		claimCode := r.URL.Query().Get("claim_code")
		if claimCode == "" {
			claimCode = r.FormValue("claim_code")
		}

		if claimCode == "" {
			http.Error(w, "Missing claim_code parameter", http.StatusBadRequest)
			return
		}

		// Delete file from database and get file info
		file, err := database.DeleteFileByClaimCode(db, claimCode)
		if err != nil {
			slog.Error("admin file deletion failed",
				"claim_code", redactClaimCode(claimCode),
				"error", err,
				"admin_ip", getClientIP(r),
			)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		// Validate stored filename (defense-in-depth against database corruption/compromise)
		if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
			slog.Error("stored filename validation failed",
				"filename", file.StoredFilename,
				"error", err,
				"claim_code", redactClaimCode(claimCode),
				"admin_ip", getClientIP(r),
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Delete physical file
		filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)
		if err := os.Remove(filePath); err != nil {
			if !os.IsNotExist(err) {
				slog.Error("failed to delete physical file",
					"path", filePath,
					"error", err,
				)
			}
		}

		// Emit webhook event for file deletion
		reason := "manually deleted by admin"
		EmitWebhookEvent(&webhooks.Event{
			Type:      webhooks.EventFileDeleted,
			Timestamp: time.Now(),
			File: webhooks.FileData{
				ID:        file.ID,
				ClaimCode: claimCode,
				Filename:  file.OriginalFilename,
				Size:      file.FileSize,
				MimeType:  file.MimeType,
				ExpiresAt: file.ExpiresAt,
				Reason:    &reason,
			},
		})

		slog.Info("admin deleted file",
			"claim_code", redactClaimCode(claimCode),
			"filename", file.OriginalFilename,
			"size", file.FileSize,
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "File deleted successfully",
		})
	}
}

// AdminBulkDeleteFilesHandler deletes multiple files
func AdminBulkDeleteFilesHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Get comma-separated claim codes
		claimCodesStr := r.FormValue("claim_codes")
		if claimCodesStr == "" {
			http.Error(w, "Missing claim_codes parameter", http.StatusBadRequest)
			return
		}

		// Split claim codes
		claimCodes := splitAndTrim(claimCodesStr, ",")
		if len(claimCodes) == 0 {
			http.Error(w, "No claim codes provided", http.StatusBadRequest)
			return
		}

		// Delete files from database and get file info
		files, err := database.DeleteFilesByClaimCodes(db, claimCodes)
		if err != nil {
			slog.Error("admin bulk file deletion failed",
				"count", len(claimCodes),
				"error", err,
				"admin_ip", getClientIP(r),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete physical files
		deletedCount := 0
		for _, file := range files {
			// Validate stored filename (defense-in-depth against database corruption/compromise)
			if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
				slog.Error("stored filename validation failed during bulk deletion",
					"filename", file.StoredFilename,
					"error", err,
					"admin_ip", getClientIP(r),
				)
				// Skip this file but continue with others
				continue
			}

			filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)
			if err := os.Remove(filePath); err != nil {
				if !os.IsNotExist(err) {
					slog.Error("failed to delete physical file",
						"path", filePath,
						"error", err,
					)
				}
			}

			// Emit webhook event for file deletion
			reason := "bulk deleted by admin"
			EmitWebhookEvent(&webhooks.Event{
				Type:      webhooks.EventFileDeleted,
				Timestamp: time.Now(),
				File: webhooks.FileData{
					ID:        file.ID,
					ClaimCode: file.ClaimCode,
					Filename:  file.OriginalFilename,
					Size:      file.FileSize,
					MimeType:  file.MimeType,
					ExpiresAt: file.ExpiresAt,
					Reason:    &reason,
				},
			})

			deletedCount++
		}

		slog.Info("admin bulk deleted files",
			"deleted_count", deletedCount,
			"requested_count", len(claimCodes),
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":       true,
			"deleted_count": deletedCount,
			"message":       fmt.Sprintf("Successfully deleted %d file(s)", deletedCount),
		})
	}
}

// AdminBlockIPHandler blocks an IP address
func AdminBlockIPHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		ipAddress := r.FormValue("ip_address")
		reason := r.FormValue("reason")

		if ipAddress == "" {
			http.Error(w, "Missing ip_address parameter", http.StatusBadRequest)
			return
		}

		if reason == "" {
			reason = "Blocked by admin"
		}

		err := database.BlockIP(db, ipAddress, reason, "admin")
		if err != nil {
			slog.Error("failed to block IP",
				"ip_address", ipAddress,
				"error", err,
			)
			http.Error(w, "Failed to block IP", http.StatusInternalServerError)
			return
		}

		slog.Info("admin blocked IP",
			"blocked_ip", ipAddress,
			"reason", reason,
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "IP blocked successfully",
		})
	}
}

// AdminUnblockIPHandler unblocks an IP address
func AdminUnblockIPHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ipAddress := r.URL.Query().Get("ip_address")
		if ipAddress == "" {
			if err := r.ParseForm(); err == nil {
				ipAddress = r.FormValue("ip_address")
			}
		}

		if ipAddress == "" {
			http.Error(w, "Missing ip_address parameter", http.StatusBadRequest)
			return
		}

		err := database.UnblockIP(db, ipAddress)
		if err != nil {
			slog.Error("failed to unblock IP",
				"ip_address", ipAddress,
				"error", err,
			)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		slog.Info("admin unblocked IP",
			"unblocked_ip", ipAddress,
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "IP unblocked successfully",
		})
	}
}

// AdminUpdateQuotaHandler updates the storage quota dynamically
func AdminUpdateQuotaHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		quotaGB := r.FormValue("quota_gb")
		if quotaGB == "" {
			http.Error(w, "Missing quota_gb parameter", http.StatusBadRequest)
			return
		}

		newQuota, err := strconv.ParseInt(quotaGB, 10, 64)
		if err != nil || newQuota < 0 {
			http.Error(w, "Invalid quota value - must be non-negative integer", http.StatusBadRequest)
			return
		}

		oldQuota := cfg.GetQuotaLimitGB()

		// Update in-memory config
		if err := cfg.SetQuotaLimitGB(newQuota); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Persist to database for restart persistence
		if err := database.UpdateQuotaSetting(db, newQuota); err != nil {
			slog.Error("failed to persist quota setting to database",
				"error", err,
				"quota_gb", newQuota,
			)
			// Don't fail the request - config is updated, just log the error
		}

		slog.Info("admin updated storage quota",
			"old_quota_gb", oldQuota,
			"new_quota_gb", newQuota,
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      true,
			"message":      "Quota updated successfully",
			"old_quota_gb": oldQuota,
			"new_quota_gb": newQuota,
		})
	}
}

// AdminUpdateStorageSettingsHandler updates storage-related settings dynamically
func AdminUpdateStorageSettingsHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Get old values for audit log
		oldQuota := cfg.GetQuotaLimitGB()
		oldMaxFileSize := cfg.GetMaxFileSize()
		oldDefaultExpiration := cfg.GetDefaultExpirationHours()
		oldMaxExpiration := cfg.GetMaxExpirationHours()

		updates := make(map[string]interface{})

		// Update storage quota
		if quotaGB := r.FormValue("quota_gb"); quotaGB != "" {
			quota, err := strconv.ParseInt(quotaGB, 10, 64)
			if err != nil || quota < 0 {
				http.Error(w, "Invalid quota_gb - must be non-negative integer", http.StatusBadRequest)
				return
			}
			if err := cfg.SetQuotaLimitGB(quota); err != nil {
				http.Error(w, "Storage quota: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Persist to database for restart persistence
			if err := database.UpdateQuotaSetting(db, quota); err != nil {
				slog.Error("failed to persist quota setting to database",
					"error", err,
					"quota_gb", quota,
				)
				// Don't fail the request - config is updated, just log the error
			}

			updates["quota_gb"] = map[string]int64{
				"old": oldQuota,
				"new": quota,
			}
		}

		// Update max file size (in MB, convert to bytes)
		if maxFileSizeMB := r.FormValue("max_file_size_mb"); maxFileSizeMB != "" {
			sizeMB, err := strconv.ParseInt(maxFileSizeMB, 10, 64)
			if err != nil || sizeMB <= 0 {
				http.Error(w, "Invalid max_file_size_mb - must be positive integer", http.StatusBadRequest)
				return
			}
			sizeBytes := sizeMB * 1024 * 1024
			if err := cfg.SetMaxFileSize(sizeBytes); err != nil {
				http.Error(w, "Max file size: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Persist to database for restart persistence
			if err := database.UpdateMaxFileSizeSetting(db, sizeBytes); err != nil {
				slog.Error("failed to persist max file size setting to database",
					"error", err,
					"max_file_size_bytes", sizeBytes,
				)
				// Don't fail the request - config is updated, just log the error
			}

			updates["max_file_size_mb"] = map[string]int64{
				"old": oldMaxFileSize / 1024 / 1024,
				"new": sizeMB,
			}
		}

		// Update default expiration
		if defaultExpStr := r.FormValue("default_expiration_hours"); defaultExpStr != "" {
			hours, err := strconv.Atoi(defaultExpStr)
			if err != nil || hours <= 0 {
				http.Error(w, "Invalid default_expiration_hours - must be positive integer", http.StatusBadRequest)
				return
			}
			if err := cfg.SetDefaultExpirationHours(hours); err != nil {
				http.Error(w, "Default expiration: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Persist to database for restart persistence
			if err := database.UpdateDefaultExpirationSetting(db, hours); err != nil {
				slog.Error("failed to persist default expiration setting to database",
					"error", err,
					"default_expiration_hours", hours,
				)
				// Don't fail the request - config is updated, just log the error
			}

			updates["default_expiration_hours"] = map[string]int{
				"old": oldDefaultExpiration,
				"new": hours,
			}
		}

		// Update max expiration
		if maxExpStr := r.FormValue("max_expiration_hours"); maxExpStr != "" {
			hours, err := strconv.Atoi(maxExpStr)
			if err != nil || hours <= 0 {
				http.Error(w, "Invalid max_expiration_hours - must be positive integer", http.StatusBadRequest)
				return
			}
			if err := cfg.SetMaxExpirationHours(hours); err != nil {
				http.Error(w, "Max expiration: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Persist to database for restart persistence
			if err := database.UpdateMaxExpirationSetting(db, hours); err != nil {
				slog.Error("failed to persist max expiration setting to database",
					"error", err,
					"max_expiration_hours", hours,
				)
				// Don't fail the request - config is updated, just log the error
			}

			updates["max_expiration_hours"] = map[string]int{
				"old": oldMaxExpiration,
				"new": hours,
			}
		}

		if len(updates) == 0 {
			http.Error(w, "No settings provided to update", http.StatusBadRequest)
			return
		}

		slog.Info("admin updated storage settings",
			"updates", updates,
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Storage settings updated successfully",
			"updates": updates,
		})
	}
}

// AdminUpdateSecuritySettingsHandler updates security-related settings dynamically
func AdminUpdateSecuritySettingsHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Get old values for audit log
		oldUploadLimit := cfg.GetRateLimitUpload()
		oldDownloadLimit := cfg.GetRateLimitDownload()
		oldBlockedExts := cfg.GetBlockedExtensions()

		updates := make(map[string]interface{})

		// Update upload rate limit
		if uploadLimitStr := r.FormValue("rate_limit_upload"); uploadLimitStr != "" {
			limit, err := strconv.Atoi(uploadLimitStr)
			if err != nil || limit <= 0 {
				http.Error(w, "Invalid rate_limit_upload - must be positive integer", http.StatusBadRequest)
				return
			}
			if err := cfg.SetRateLimitUpload(limit); err != nil {
				http.Error(w, "Upload rate limit: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Persist to database for restart persistence
			if err := database.UpdateRateLimitUploadSetting(db, limit); err != nil {
				slog.Error("failed to persist rate limit upload setting to database",
					"error", err,
					"rate_limit_upload", limit,
				)
				// Don't fail the request - config is updated, just log the error
			}

			updates["rate_limit_upload"] = map[string]int{
				"old": oldUploadLimit,
				"new": limit,
			}
		}

		// Update download rate limit
		if downloadLimitStr := r.FormValue("rate_limit_download"); downloadLimitStr != "" {
			limit, err := strconv.Atoi(downloadLimitStr)
			if err != nil || limit <= 0 {
				http.Error(w, "Invalid rate_limit_download - must be positive integer", http.StatusBadRequest)
				return
			}
			if err := cfg.SetRateLimitDownload(limit); err != nil {
				http.Error(w, "Download rate limit: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Persist to database for restart persistence
			if err := database.UpdateRateLimitDownloadSetting(db, limit); err != nil {
				slog.Error("failed to persist rate limit download setting to database",
					"error", err,
					"rate_limit_download", limit,
				)
				// Don't fail the request - config is updated, just log the error
			}

			updates["rate_limit_download"] = map[string]int{
				"old": oldDownloadLimit,
				"new": limit,
			}
		}

		// Update blocked extensions
		if blockedExtsStr := r.FormValue("blocked_extensions"); blockedExtsStr != "" {
			// Split comma-separated list
			parts := make([]string, 0)
			for _, ext := range splitAndTrim(blockedExtsStr, ",") {
				if ext != "" {
					parts = append(parts, ext)
				}
			}
			if err := cfg.SetBlockedExtensions(parts); err != nil {
				http.Error(w, "Blocked extensions: "+err.Error(), http.StatusBadRequest)
				return
			}

			// Persist to database for restart persistence
			if err := database.UpdateBlockedExtensionsSetting(db, cfg.GetBlockedExtensions()); err != nil {
				slog.Error("failed to persist blocked extensions setting to database",
					"error", err,
					"blocked_extensions", cfg.GetBlockedExtensions(),
				)
				// Don't fail the request - config is updated, just log the error
			}

			updates["blocked_extensions"] = map[string]interface{}{
				"old": oldBlockedExts,
				"new": cfg.GetBlockedExtensions(),
			}
		}

		if len(updates) == 0 {
			http.Error(w, "No settings provided to update", http.StatusBadRequest)
			return
		}

		slog.Info("admin updated security settings",
			"updates", updates,
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Security settings updated successfully",
			"updates": updates,
		})
	}
}

// AdminChangePasswordHandler allows the admin to change their password
func AdminChangePasswordHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		// Validate inputs
		if currentPassword == "" || newPassword == "" || confirmPassword == "" {
			http.Error(w, "All password fields are required", http.StatusBadRequest)
			return
		}

		// Verify current password using constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(currentPassword), []byte(cfg.GetAdminPassword())) != 1 {
			slog.Warn("admin password change failed - incorrect current password",
				"admin_ip", getClientIP(r),
			)
			time.Sleep(500 * time.Millisecond) // Additional defense against timing attacks
			http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
			return
		}

		// Verify new password matches confirmation
		if newPassword != confirmPassword {
			http.Error(w, "New password and confirmation do not match", http.StatusBadRequest)
			return
		}

		// Validate new password length
		if err := cfg.SetAdminPassword(newPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		slog.Info("admin password changed successfully",
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Password changed successfully. Please log in again with your new password.",
		})
	}
}

// Helper function to split and trim strings
func splitAndTrim(s, sep string) []string {
	parts := make([]string, 0)
	for _, part := range splitByComma(s) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func splitByComma(s string) []string {
	result := make([]string, 0)
	current := ""
	for _, ch := range s {
		if ch == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

// AdminGetConfigHandler returns current configuration values for the settings forms
func AdminGetConfigHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"max_file_size_bytes":      cfg.GetMaxFileSize(),
			"default_expiration_hours": cfg.GetDefaultExpirationHours(),
			"max_expiration_hours":     cfg.GetMaxExpirationHours(),
			"rate_limit_upload":        cfg.GetRateLimitUpload(),
			"rate_limit_download":      cfg.GetRateLimitDownload(),
			"blocked_extensions":       cfg.GetBlockedExtensions(),
			"quota_limit_gb":           cfg.GetQuotaLimitGB(),
		})
	}
}

// AdminCleanupPartialUploadsHandler cleans up abandoned partial uploads
func AdminCleanupPartialUploadsHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		clientIP := getClientIP(r)

		// Admin-initiated cleanup should be immediate (0 hours = clean up ALL incomplete uploads)
		// Background worker uses cfg.PartialUploadExpiryHours for automatic cleanup
		expiryHours := 0

		slog.Info("admin initiated partial uploads cleanup (immediate)",
			"admin_ip", clientIP,
			"expiry_hours", expiryHours,
		)

		// Clean up abandoned uploads
		result, err := utils.CleanupAbandonedUploads(db, cfg.UploadDir, expiryHours)
		if err != nil {
			slog.Error("failed to cleanup partial uploads",
				"error", err,
				"admin_ip", clientIP,
			)
			http.Error(w, "Failed to cleanup partial uploads", http.StatusInternalServerError)
			return
		}

		slog.Info("admin completed partial uploads cleanup",
			"deleted_count", result.DeletedCount,
			"abandoned_count", result.AbandonedCount,
			"orphaned_chunks_count", result.OrphanedCount,
			"orphaned_files_count", result.OrphanedFilesCount,
			"bytes_reclaimed", result.BytesReclaimed,
			"orphaned_chunk_bytes", result.OrphanedBytes,
			"orphaned_file_bytes", result.OrphanedFilesBytes,
			"admin_ip", clientIP,
		)

		// Format the success message with breakdown
		var message string
		if result.OrphanedCount > 0 || result.OrphanedFilesCount > 0 {
			message = fmt.Sprintf("Cleaned up %d upload(s) (%d abandoned, %d orphaned chunks, %d orphaned files), reclaimed %s",
				result.DeletedCount+result.OrphanedFilesCount,
				result.AbandonedCount,
				result.OrphanedCount,
				result.OrphanedFilesCount,
				utils.FormatBytes(uint64(result.BytesReclaimed)),
			)
		} else {
			message = fmt.Sprintf("Cleaned up %d abandoned upload(s), reclaimed %s",
				result.DeletedCount,
				utils.FormatBytes(uint64(result.BytesReclaimed)),
			)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":              true,
			"deleted_count":        result.DeletedCount,
			"abandoned_count":      result.AbandonedCount,
			"orphaned_chunks_count": result.OrphanedCount,
			"orphaned_files_count":  result.OrphanedFilesCount,
			"bytes_reclaimed":      result.BytesReclaimed,
			"orphaned_chunk_bytes": result.OrphanedBytes,
			"orphaned_file_bytes":  result.OrphanedFilesBytes,
			"message":              message,
		})
	}
}
