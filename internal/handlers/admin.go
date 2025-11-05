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
	"time"

	"github.com/yourusername/safeshare/internal/config"
	"github.com/yourusername/safeshare/internal/database"
	"github.com/yourusername/safeshare/internal/middleware"
	"github.com/yourusername/safeshare/internal/models"
	"github.com/yourusername/safeshare/internal/utils"
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

		// Validate credentials against database
		valid, err := database.ValidateAdminCredentials(db, username, password)
		if err != nil || !valid {
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

		// Store session in database
		err = database.CreateSession(db, sessionToken, expiresAt, clientIP, userAgent)
		if err != nil {
			slog.Error("failed to create session", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_session",
			Value:    sessionToken,
			Path:     "/admin",
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
			SameSite: http.SameSiteStrictMode,
			Expires:  expiresAt,
		})

		// Generate and set CSRF token
		csrfToken, err := middleware.SetCSRFCookie(w)
		if err != nil {
			slog.Error("failed to set CSRF cookie", "error", err)
		}

		slog.Info("admin login successful",
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
	}
}

// AdminLogoutHandler handles admin logout
func AdminLogoutHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get session cookie
		cookie, err := r.Cookie("admin_session")
		if err == nil {
			// Delete session from database
			database.DeleteSession(db, cookie.Value)

			slog.Info("admin logout",
				"ip", getClientIP(r),
			)
		}

		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_session",
			Value:    "",
			Path:     "/admin",
			HttpOnly: true,
			MaxAge:   -1, // Delete cookie
		})

		// Clear CSRF cookie
		http.SetCookie(w, &http.Cookie{
			Name:   "csrf_token",
			Value:  "",
			Path:   "/admin",
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

		pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		if pageSize < 1 || pageSize > 100 {
			pageSize = 20
		}

		searchTerm := r.URL.Query().Get("search")

		offset := (page - 1) * pageSize

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

		// Calculate quota usage
		var quotaLimitBytes int64
		var quotaUsedPercent float64
		if cfg.GetQuotaLimitGB() > 0 {
			quotaLimitBytes = cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024
			if quotaLimitBytes > 0 {
				quotaUsedPercent = (float64(storageUsed) / float64(quotaLimitBytes)) * 100
			}
		}

		// Prepare response with file details
		type FileResponse struct {
			ID                int64     `json:"id"`
			ClaimCode         string    `json:"claim_code"`
			OriginalFilename  string    `json:"original_filename"`
			FileSize          int64     `json:"file_size"`
			MimeType          string    `json:"mime_type"`
			CreatedAt         time.Time `json:"created_at"`
			ExpiresAt         time.Time `json:"expires_at"`
			MaxDownloads      *int      `json:"max_downloads"`
			DownloadCount     int       `json:"download_count"`
			Username          *string   `json:"username"`           // nullable - nil for anonymous uploads
			UploaderIP        string    `json:"uploader_ip"`
			PasswordProtected bool      `json:"password_protected"`
		}

		fileResponses := make([]FileResponse, len(files))
		for i, file := range files {
			fileResponses[i] = FileResponse{
				ID:                file.ID,
				ClaimCode:         file.ClaimCode,
				OriginalFilename:  file.OriginalFilename,
				FileSize:          file.FileSize,
				MimeType:          file.MimeType,
				CreatedAt:         file.CreatedAt,
				ExpiresAt:         file.ExpiresAt,
				MaxDownloads:      file.MaxDownloads,
				DownloadCount:     file.DownloadCount,
				Username:          file.Username,
				UploaderIP:        file.UploaderIP,
				PasswordProtected: file.PasswordHash != "",
			}
		}

		response := map[string]interface{}{
			"files":              fileResponses,
			"pagination": map[string]interface{}{
				"page":       page,
				"page_size":  pageSize,
				"total":      total,
				"total_pages": (total + pageSize - 1) / pageSize,
			},
			"stats": map[string]interface{}{
				"total_files":        totalFiles,
				"storage_used_bytes": storageUsed,
				"quota_limit_bytes":  quotaLimitBytes,
				"quota_used_percent": quotaUsedPercent,
			},
			"blocked_ips": blockedIPs,
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
			filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)
			if err := os.Remove(filePath); err != nil {
				if !os.IsNotExist(err) {
					slog.Error("failed to delete physical file",
						"path", filePath,
						"error", err,
					)
				}
			}
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
func AdminUpdateQuotaHandler(cfg *config.Config) http.HandlerFunc {
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

		if err := cfg.SetQuotaLimitGB(newQuota); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
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
func AdminUpdateStorageSettingsHandler(cfg *config.Config) http.HandlerFunc {
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
func AdminUpdateSecuritySettingsHandler(cfg *config.Config) http.HandlerFunc {
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

		// Verify current password
		if currentPassword != cfg.GetAdminPassword() {
			slog.Warn("admin password change failed - incorrect current password",
				"admin_ip", getClientIP(r),
			)
			time.Sleep(500 * time.Millisecond) // Prevent timing attacks
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
			"max_file_size_bytes":       cfg.GetMaxFileSize(),
			"default_expiration_hours":  cfg.GetDefaultExpirationHours(),
			"max_expiration_hours":      cfg.GetMaxExpirationHours(),
			"rate_limit_upload":         cfg.GetRateLimitUpload(),
			"rate_limit_download":       cfg.GetRateLimitDownload(),
			"blocked_extensions":        cfg.GetBlockedExtensions(),
			"quota_limit_gb":            cfg.GetQuotaLimitGB(),
		})
	}
}
