package handlers

import (
	"database/sql"
	"encoding/json"
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

		// Parse form data
		if err := r.ParseForm(); err != nil {
			slog.Error("failed to parse login form", "error", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		clientIP := getClientIP(r)
		userAgent := getUserAgent(r)

		// Validate credentials
		if username != cfg.AdminUsername || password != cfg.AdminPassword {
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
		if cfg.QuotaLimitGB > 0 {
			quotaLimitBytes = cfg.QuotaLimitGB * 1024 * 1024 * 1024
			if quotaLimitBytes > 0 {
				quotaUsedPercent = (float64(storageUsed) / float64(quotaLimitBytes)) * 100
			}
		}

		// Prepare response with file details
		type FileResponse struct {
			ID               int64     `json:"id"`
			ClaimCode        string    `json:"claim_code"`
			OriginalFilename string    `json:"original_filename"`
			FileSize         int64     `json:"file_size"`
			MimeType         string    `json:"mime_type"`
			CreatedAt        time.Time `json:"created_at"`
			ExpiresAt        time.Time `json:"expires_at"`
			MaxDownloads     *int      `json:"max_downloads"`
			DownloadCount    int       `json:"download_count"`
			UploaderIP       string    `json:"uploader_ip"`
			PasswordProtected bool     `json:"password_protected"`
		}

		fileResponses := make([]FileResponse, len(files))
		for i, file := range files {
			fileResponses[i] = FileResponse{
				ID:               file.ID,
				ClaimCode:        file.ClaimCode,
				OriginalFilename: file.OriginalFilename,
				FileSize:         file.FileSize,
				MimeType:         file.MimeType,
				CreatedAt:        file.CreatedAt,
				ExpiresAt:        file.ExpiresAt,
				MaxDownloads:     file.MaxDownloads,
				DownloadCount:    file.DownloadCount,
				UploaderIP:       file.UploaderIP,
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

		oldQuota := cfg.QuotaLimitGB
		cfg.QuotaLimitGB = newQuota

		slog.Info("admin updated storage quota",
			"old_quota_gb", oldQuota,
			"new_quota_gb", newQuota,
			"admin_ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Quota updated successfully",
			"old_quota_gb": oldQuota,
			"new_quota_gb": newQuota,
		})
	}
}
