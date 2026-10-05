package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/ipcanon"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/proxytrust"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// AdminLoginHandler handles admin login
func AdminLoginHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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
		userAgent := storeUserAgent(getUserAgent(r), cfg)

		// Track authentication method and user (if applicable)
		var authenticatedUser *models.User
		isAdminCredentials := false

		// Try validating against admin_credentials table first
		valid, err := repos.Admin.ValidateCredentials(ctx, username, password)
		if err == nil && valid {
			isAdminCredentials = true
		} else {
			// Try to get user from users table with admin role
			user, userErr := repos.Users.GetByUsername(ctx, username)

			if userErr != nil {
				user = nil
			}

			// Check password (verifyUserPassword runs bcrypt even for an
			// unknown username, so timing doesn't reveal which exist), admin
			// role, and active status
			if verifyUserPassword(user, password) &&
				user.Role == "admin" &&
				user.IsActive {
				// User authenticated successfully with admin role
				authenticatedUser = user
				slog.Info("admin login successful via users table",
					"username", logUsername(username, cfg),
					"user_id", user.ID,
					"ip", logIP(clientIP, cfg),
				)
			}
		}

		// If both authentication methods failed
		if !isAdminCredentials && authenticatedUser == nil {
			slog.Warn("admin login failed - invalid credentials",
				"username", logUsername(username, cfg),
				"ip", logIP(clientIP, cfg),
			)
			audit.Record(r, cfg, audit.Event{Type: models.AuditEventAuth, Action: "admin_login", Outcome: models.AuditOutcomeFailure,
				Username: username, ResourceType: "user", Details: map[string]any{"reason": "invalid_credentials"}})

			// Return error with slight delay to prevent timing attacks
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid username or password",
			})
			return
		}

		// Check MFA for database admin users (not env-based admin credentials)
		// Only check MFA if the global MFA feature is enabled
		// Use GetMFAConfig() for thread-safe access to avoid race conditions
		mfaCfg := cfg.GetMFAConfig()
		if authenticatedUser != nil && mfaCfg != nil && mfaCfg.Enabled {
			mfaStatus, err := repos.MFA.GetMFAStatus(ctx, authenticatedUser.ID)
			if err == nil && mfaStatus != nil {
				var availableMethods []string
				if mfaStatus.TOTPEnabled {
					availableMethods = append(availableMethods, "totp")
				}
				if mfaStatus.WebAuthnEnabled {
					availableMethods = append(availableMethods, "webauthn")
				}

				// If MFA is enabled, require verification before creating session
				if len(availableMethods) > 0 {
					availableMethods = append(availableMethods, "recovery")

					// Get MFA challenge expiry from config
					expiryMinutes := mfaChallengeExpiryMinutes
					if mfaCfg.ChallengeExpiryMinutes > 0 {
						expiryMinutes = mfaCfg.ChallengeExpiryMinutes
					}

					// Create MFA login challenge
					challengeID, err := mfaLoginStore.Create(authenticatedUser.ID, clientIP, userAgent, expiryMinutes)
					if err != nil {
						if err == ErrTooManyChallenges {
							slog.Warn("admin MFA challenge creation rate limited",
								"user_id", authenticatedUser.ID,
								"ip", logIP(clientIP, cfg),
							)
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(http.StatusTooManyRequests)
							json.NewEncoder(w).Encode(map[string]string{
								"error": "Too many login attempts. Please try again later.",
							})
							return
						}
						slog.Error("failed to create admin MFA challenge", "error", err, "user_id", authenticatedUser.ID)
						http.Error(w, "Internal server error", http.StatusInternalServerError)
						return
					}

					slog.Info("MFA challenge created for admin login",
						"username", logUsername(username, cfg),
						"user_id", authenticatedUser.ID,
						"available_methods", availableMethods,
						"ip", logIP(clientIP, cfg),
					)
					audit.Record(r, cfg, audit.Event{Type: models.AuditEventAuth, Action: "admin_login_mfa_challenge", Outcome: models.AuditOutcomeSuccess,
						UserID: authenticatedUser.ID, Username: authenticatedUser.Username, ResourceType: "user",
						ResourceID: strconv.FormatInt(authenticatedUser.ID, 10)})

					// Determine primary challenge type
					challengeType := "totp"
					if len(availableMethods) > 0 && availableMethods[0] == "webauthn" {
						challengeType = "webauthn"
					}

					// Return MFA required response
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]interface{}{
						"mfa_required":      true,
						"challenge_id":      challengeID,
						"challenge_type":    challengeType,
						"available_methods": availableMethods,
						"expires_in":        expiryMinutes * 60,
						"message":           "Please verify your identity to complete login",
					})
					return
				}
			}
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
			err = repos.Admin.CreateSession(ctx, sessionToken, expiresAt, storeIP(clientIP, cfg), userAgent)
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
				"username", logUsername(username, cfg),
				"ip", logIP(clientIP, cfg),
				"user_agent", userAgent,
			)
			audit.Record(r, cfg, audit.Event{Type: models.AuditEventAuth, Action: "admin_login", Outcome: models.AuditOutcomeSuccess,
				Username: username, ResourceType: "user", Details: map[string]any{"method": "admin_credentials"}})

			// Return success response with CSRF token
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":    true,
				"csrf_token": csrfToken,
			})
		} else {
			// Users table path: create user_session for better compatibility
			err = repos.Users.CreateSession(ctx, authenticatedUser.ID, sessionToken, expiresAt, storeIP(clientIP, cfg), userAgent)
			if err != nil {
				slog.Error("failed to create user session", "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// Update last login timestamp
			if err := repos.Users.UpdateLastLogin(ctx, authenticatedUser.ID); err != nil {
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

			audit.Record(r, cfg, audit.Event{Type: models.AuditEventAuth, Action: "admin_login", Outcome: models.AuditOutcomeSuccess,
				UserID: authenticatedUser.ID, Username: authenticatedUser.Username, ResourceType: "user",
				ResourceID: strconv.FormatInt(authenticatedUser.ID, 10)})

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
func AdminLogoutHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Check for admin_session cookie (legacy admin_credentials login)
		adminCookie, adminErr := r.Cookie("admin_session")
		if adminErr == nil {
			// Delete admin session from database
			if err := repos.Admin.DeleteSession(ctx, adminCookie.Value); err != nil {
				slog.Error("failed to delete admin session", "error", err)
			}

			slog.Info("admin logout via admin_session",
				"ip", logIP(getClientIP(r), cfg),
			)
		}

		// Check for user_session cookie (users table with admin role)
		userCookie, userErr := r.Cookie("user_session")
		if userErr == nil {
			// Delete user session from database
			if err := repos.Users.DeleteSession(ctx, userCookie.Value); err != nil {
				slog.Error("failed to delete user session", "error", err)
			}

			slog.Info("admin logout via user_session",
				"ip", logIP(getClientIP(r), cfg),
			)
		}

		recordAdmin(r, cfg, audit.Event{Type: models.AuditEventAuth, Action: "admin_logout", Outcome: models.AuditOutcomeSuccess,
			ResourceType: "user"})

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
func AdminDashboardDataHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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
			files, total, err = repos.Files.SearchForAdmin(ctx, searchTerm, pageSize, offset)
		} else {
			files, total, err = repos.Files.GetAllForAdmin(ctx, pageSize, offset)
		}

		if err != nil {
			slog.Error("failed to get files for admin", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get storage stats
		stats, err := repos.Files.GetStats(ctx, cfg.UploadDir)
		var totalFiles int
		var storageUsed int64
		if err != nil {
			slog.Error("failed to get storage stats", "error", err)
			// Continue with partial data
		} else {
			totalFiles = stats.TotalFiles
			storageUsed = stats.StorageUsed
		}

		// Get blocked IPs
		blockedIPs, err := repos.Admin.GetBlockedIPs(ctx)
		if err != nil {
			slog.Error("failed to get blocked IPs", "error", err)
			blockedIPs = []repository.BlockedIP{}
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

		partialUploadsCount, err := repos.PartialUploads.GetIncompleteCount(ctx)
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
			ScanStatus         string    `json:"scan_status"`
			ScanResult         string    `json:"scan_result"`
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
				UploaderIP:         logIP(file.UploaderIP, cfg),
				PasswordProtected:  file.PasswordHash != "",
				ScanStatus:         file.ScanStatus,
				ScanResult:         file.ScanResult,
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
func AdminDeleteFileHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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
		file, err := repos.Files.DeleteByClaimCode(ctx, claimCode)
		if err != nil {
			slog.Error("admin file deletion failed",
				"claim_code", redactClaimCode(claimCode),
				"error", err,
				"admin_ip", logIP(getClientIP(r), cfg),
			)
			// Security fix: Use generic error message to avoid leaking internal details
			http.Error(w, "File not found or already deleted", http.StatusNotFound)
			return
		}

		// Validate stored filename (defense-in-depth against database corruption/compromise)
		if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
			slog.Error("stored filename validation failed",
				"filename", file.StoredFilename,
				"error", err,
				"claim_code", redactClaimCode(claimCode),
				"admin_ip", logIP(getClientIP(r), cfg),
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
			"filename", logFilename(file.OriginalFilename, cfg),
			"size", file.FileSize,
			"admin_ip", logIP(getClientIP(r), cfg),
		)
		recordAdmin(r, cfg, audit.Event{Action: "file_delete", Outcome: models.AuditOutcomeSuccess,
			ResourceType: "file", ResourceID: strconv.FormatInt(file.ID, 10)})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "File deleted successfully",
		})
	}
}

// AdminBulkDeleteFilesHandler deletes multiple files
func AdminBulkDeleteFilesHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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
		files, err := repos.Files.DeleteByClaimCodes(ctx, claimCodes)
		if err != nil {
			slog.Error("admin bulk file deletion failed",
				"count", len(claimCodes),
				"error", err,
				"admin_ip", logIP(getClientIP(r), cfg),
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Delete physical files
		deletedCount := 0
		deletedIDs := make([]int64, 0, len(files))
		for _, file := range files {
			// Validate stored filename (defense-in-depth against database corruption/compromise)
			if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
				slog.Error("stored filename validation failed during bulk deletion",
					"filename", file.StoredFilename,
					"error", err,
					"admin_ip", logIP(getClientIP(r), cfg),
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
			deletedIDs = append(deletedIDs, file.ID)
		}

		slog.Info("admin bulk deleted files",
			"deleted_count", deletedCount,
			"requested_count", len(claimCodes),
			"admin_ip", logIP(getClientIP(r), cfg),
		)
		recordAdmin(r, cfg, audit.Event{Action: "file_bulk_delete", Outcome: models.AuditOutcomeSuccess, ResourceType: "file",
			Details: map[string]any{"count": deletedCount, "ids": capIDs(deletedIDs, auditMaxIDs)}})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":       true,
			"deleted_count": deletedCount,
			"message":       fmt.Sprintf("Successfully deleted %d file(s)", deletedCount),
		})
	}
}

// loopbackPrefixes are the ranges selfLockoutCheck refuses to let an admin
// block: doing so would very likely break local health checks and/or the
// admin's own access when the deployment sits behind a reverse proxy or
// tunnel on loopback (T43).
var loopbackPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// adminIPAPIResponse is the JSON body AdminBlockIPHandler and
// AdminUnblockIPHandler always reply with, success or failure -- admin.js's
// blockIP/unblockIP read response.json().message on any non-success reply
// (code-review follow-up: they used to get http.Error's plain-text body,
// which response.json() can't parse, so every failure surfaced as the same
// generic "Failed to block/unblock IP" regardless of the real reason).
type adminIPAPIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// writeAdminIPResponse writes an adminIPAPIResponse with the given status.
func writeAdminIPResponse(w http.ResponseWriter, status int, success bool, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(adminIPAPIResponse{Success: success, Message: message}) //nolint:errcheck // best-effort; client may have disconnected
}

// selfLockoutCheck returns a non-nil err if blocking entry (canonical,
// isPrefix) would block loopback, fully contain a configured
// TRUSTED_PROXY_IPS entry, or include the requesting admin's own current
// client IP -- all three would very likely lock the operator out of the
// admin dashboard entirely (directly, or by breaking the proxy-trust chain
// GetClientIPWithTrust relies on), with no way to undo it except direct
// DB/file access (T43). adminIP is the admin's own current client IP (as
// seen by this request); trustedProxies is the parsed TRUSTED_PROXY_IPS list
// (local ranges, plus Cloudflare's published ranges if the "cloudflare"
// keyword is configured -- see proxytrust.ParseList). Either being
// unparsable/empty just skips that particular check rather than failing the
// request.
//
// The TRUSTED_PROXY_IPS check (code-review follow-up) is deliberately
// narrower than "any overlap": the default value is whole private ranges
// (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and refusing any overlap with
// those would stop an admin on a LAN deployment from blocking even a single
// misbehaving LAN host. After T41, blocking an address inside a trusted
// range only matters for requests that fall back to that proxy's own peer
// address -- i.e. ones with no, or no usable, forwarded header (see
// GetClientIPWithTrust) -- so:
//
//   - Refusing is limited to a target that fully contains a trusted entry
//     (proxytrust.PrefixContains): blocking the trusted range/host itself
//     (e.g. 10.0.0.0/8, or a /16 that contains a trusted /24), or blocking a
//     range that contains a trusted entry which is itself a single host
//     (/32 or /128) -- an explicitly named proxy, where "contains" and
//     "equals" are the same thing at that granularity.
//   - A target that merely sits inside a broader trusted range (e.g. a
//     single LAN host under the default 192.168.0.0/16) is allowed, but
//     flagged via the non-empty caution return value so the caller can warn
//     the admin: if that range is (or includes) their actual reverse
//     proxy's peer address, its own no-forwarded-header requests will now be
//     blocked.
//
// Two CIDR prefixes never partially overlap (see PrefixContains's doc), so
// "overlaps but doesn't fully contain" and "is fully contained by" are the
// same condition -- checking Overlaps then PrefixContains(target, tp)
// is sufficient to tell the two cases apart.
func selfLockoutCheck(canonical string, isPrefix bool, adminIP string, trustedProxies []netip.Prefix) (caution string, err error) {
	var target netip.Prefix
	if isPrefix {
		p, perr := netip.ParsePrefix(canonical)
		if perr != nil {
			return "", nil // canonical is already validated by the caller; defensive only
		}
		target = p
	} else {
		addr, aerr := netip.ParseAddr(canonical)
		if aerr != nil {
			return "", nil
		}
		target = netip.PrefixFrom(addr, addr.BitLen())
	}

	for _, lb := range loopbackPrefixes {
		if target.Overlaps(lb) {
			return "", fmt.Errorf("refusing to block %s: it includes loopback (127.0.0.0/8 or ::1), which would likely break local health checks and/or admin access", canonical)
		}
	}

	for _, tp := range trustedProxies {
		if !target.Overlaps(tp) {
			continue
		}
		if proxytrust.PrefixContains(target, tp) {
			return "", fmt.Errorf("refusing to block %s: it fully contains a TRUSTED_PROXY_IPS entry (%s) that SafeShare relies on to resolve real client IPs, which would break request handling for every client behind it", canonical, tp)
		}
		// target sits inside the broader tp -- allowed, but worth a warning.
		caution = fmt.Sprintf("Note: %s is inside the configured TRUSTED_PROXY_IPS range %s. If that range includes your reverse proxy, any of its requests that arrive without a usable forwarded header will now be blocked too.", canonical, tp)
	}

	if adminAddr, aerr := netip.ParseAddr(adminIP); aerr == nil {
		if target.Contains(adminAddr) {
			return "", fmt.Errorf("refusing to block %s: it includes your own current IP address, which would lock you out of the admin dashboard", canonical)
		}
	}

	return caution, nil
}

// AdminBlockIPHandler blocks an IP address or CIDR range.
func AdminBlockIPHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		if err := r.ParseForm(); err != nil {
			writeAdminIPResponse(w, http.StatusBadRequest, false, "Bad request")
			return
		}

		ipAddress := strings.TrimSpace(r.FormValue("ip_address"))
		reason := r.FormValue("reason")

		if ipAddress == "" {
			writeAdminIPResponse(w, http.StatusBadRequest, false, "Missing ip_address parameter")
			return
		}

		// T43: accepts a bare IP address or a CIDR range, canonicalized
		// (and, for a CIDR, bounds-checked against self-lockout-by-typo --
		// e.g. "10.0.0.0/4") by ipcanon.CanonicalizeEntry. The canonical
		// form is what selfLockoutCheck below and repos.Admin.BlockIP both
		// operate on.
		canonical, isPrefix, err := ipcanon.CanonicalizeEntry(ipAddress)
		if err != nil {
			writeAdminIPResponse(w, http.StatusBadRequest, false, "Invalid IP address or CIDR range: "+err.Error())
			return
		}

		// Best-effort: TRUSTED_PROXY_IPS is validated at startup
		// (config.validateProxySettings), so a parse failure here should
		// never happen in practice -- but if it somehow does, log and skip
		// that part of the check rather than failing the whole request.
		trustedProxies, tpErr := proxytrust.ParseList(cfg.GetTrustedProxyIPs())
		if tpErr != nil {
			slog.Warn("failed to parse TRUSTED_PROXY_IPS for self-lockout check; skipping that check",
				"error", tpErr,
			)
			trustedProxies = nil
		}

		caution, err := selfLockoutCheck(canonical, isPrefix, getClientIP(r), trustedProxies)
		if err != nil {
			slog.Warn("admin blocked-IP request refused: would self-lock-out",
				"requested", ipAddress,
				"canonical", canonical,
				"admin_ip", logIP(getClientIP(r), cfg),
				"error", err,
			)
			// 409: the request conflicts with the operator's own continued
			// access, not an authorization failure (403) or malformed input
			// (400) -- same status family as the "already blocked"
			// conflict below.
			writeAdminIPResponse(w, http.StatusConflict, false, err.Error())
			return
		}

		if reason == "" {
			reason = "Blocked by admin"
		}

		// Pass the already-canonicalized value rather than the raw
		// ipAddress (code-review nit): BlockIP re-canonicalizes whatever
		// it's given (so other callers can still pass raw input), but this
		// call site already computed it above for selfLockoutCheck, so
		// canonicalizing it a second time inside BlockIP would be redundant
		// (canonicalizing an already-canonical value is a no-op, just
		// wasted work).
		err = repos.Admin.BlockIP(ctx, canonical, reason, "admin")
		if err != nil {
			if errors.Is(err, repository.ErrDuplicateKey) {
				writeAdminIPResponse(w, http.StatusConflict, false, "This IP address or range is already blocked")
				return
			}
			slog.Error("failed to block IP",
				"ip_address", canonical,
				"error", err,
			)
			writeAdminIPResponse(w, http.StatusInternalServerError, false, "Failed to block IP")
			return
		}

		slog.Info("admin blocked IP",
			"blocked_ip", canonical,
			"is_cidr", isPrefix,
			"reason", reason,
			"admin_ip", logIP(getClientIP(r), cfg),
			"trusted_proxy_caution", caution != "",
		)
		recordAdmin(r, cfg, audit.Event{Action: "ip_block", Outcome: models.AuditOutcomeSuccess, ResourceType: "ip", ResourceID: canonical,
			Details: map[string]any{"is_cidr": isPrefix, "reason": reason}})

		message := "IP blocked successfully"
		if caution != "" {
			message += " " + caution
		}
		writeAdminIPResponse(w, http.StatusOK, true, message)
	}
}

// AdminUnblockIPHandler unblocks an IP address or CIDR range.
func AdminUnblockIPHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		ipAddress := r.URL.Query().Get("ip_address")
		if ipAddress == "" {
			if err := r.ParseForm(); err == nil {
				ipAddress = r.FormValue("ip_address")
			}
		}

		if ipAddress == "" {
			writeAdminIPResponse(w, http.StatusBadRequest, false, "Missing ip_address parameter")
			return
		}

		// repos.Admin.UnblockIP canonicalizes ipAddress itself, falling
		// back to an exact match on the raw string if it can't canonicalize
		// (e.g. a legacy CIDR broader than T43's bounds -- see UnblockIP's
		// doc comment) -- so the only errors it can return now are a real
		// "not found" or a genuine backend failure, not a validation error.
		err := repos.Admin.UnblockIP(ctx, ipAddress)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				writeAdminIPResponse(w, http.StatusNotFound, false, "IP not found in blocked list")
				return
			}
			slog.Error("failed to unblock IP",
				"ip_address", ipAddress,
				"error", err,
			)
			writeAdminIPResponse(w, http.StatusInternalServerError, false, "Failed to unblock IP")
			return
		}

		slog.Info("admin unblocked IP",
			"unblocked_ip", ipAddress,
			"admin_ip", logIP(getClientIP(r), cfg),
		)
		recordAdmin(r, cfg, audit.Event{Action: "ip_unblock", Outcome: models.AuditOutcomeSuccess, ResourceType: "ip", ResourceID: ipAddress})

		writeAdminIPResponse(w, http.StatusOK, true, "IP unblocked successfully")
	}
}

// AdminUpdateQuotaHandler updates the storage quota dynamically
func AdminUpdateQuotaHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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
		if err := repos.Settings.UpdateQuota(ctx, newQuota); err != nil {
			slog.Error("failed to persist quota setting to database",
				"error", err,
				"quota_gb", newQuota,
			)
			// Don't fail the request - config is updated, just log the error
		}

		slog.Info("admin updated storage quota",
			"old_quota_gb", oldQuota,
			"new_quota_gb", newQuota,
			"admin_ip", logIP(getClientIP(r), cfg),
		)
		recordAdmin(r, cfg, audit.Event{Type: models.AuditEventConfig, Action: "quota_update", Outcome: models.AuditOutcomeSuccess,
			ResourceType: "setting", ResourceID: "quota_gb", Details: map[string]any{"old_quota_gb": oldQuota, "new_quota_gb": newQuota}})

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
func AdminUpdateStorageSettingsHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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
		// Settings are applied one at a time, so record whatever was applied
		// even if a later field is rejected.
		defer func() {
			if len(updates) > 0 {
				recordAdmin(r, cfg, audit.Event{Type: models.AuditEventConfig, Action: "storage_settings_update",
					Outcome: models.AuditOutcomeSuccess, ResourceType: "setting", Details: map[string]any{"changes": updates}})
			}
		}()

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
			if err := repos.Settings.UpdateQuota(ctx, quota); err != nil {
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
			if err := repos.Settings.UpdateMaxFileSize(ctx, sizeBytes); err != nil {
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
			if err := repos.Settings.UpdateDefaultExpiration(ctx, hours); err != nil {
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
			if err := repos.Settings.UpdateMaxExpiration(ctx, hours); err != nil {
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
			"admin_ip", logIP(getClientIP(r), cfg),
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
func AdminUpdateSecuritySettingsHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		// Get old values for audit log
		oldUploadLimit := cfg.GetRateLimitUpload()
		oldDownloadLimit := cfg.GetRateLimitDownload()
		oldBlockedExts := cfg.GetBlockedExtensions()

		updates := make(map[string]interface{})
		// Settings are applied one at a time, so record whatever was applied
		// even if a later field is rejected.
		defer func() {
			if len(updates) > 0 {
				recordAdmin(r, cfg, audit.Event{Type: models.AuditEventConfig, Action: "security_settings_update",
					Outcome: models.AuditOutcomeSuccess, ResourceType: "setting", Details: map[string]any{"changes": updates}})
			}
		}()

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
			if err := repos.Settings.UpdateRateLimitUpload(ctx, limit); err != nil {
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
			if err := repos.Settings.UpdateRateLimitDownload(ctx, limit); err != nil {
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
			if err := repos.Settings.UpdateBlockedExtensions(ctx, cfg.GetBlockedExtensions()); err != nil {
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
			"admin_ip", logIP(getClientIP(r), cfg),
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
				"admin_ip", logIP(getClientIP(r), cfg),
			)
			recordAdmin(r, cfg, audit.Event{Type: models.AuditEventAuth, Action: "admin_password_change", Outcome: models.AuditOutcomeFailure,
				ResourceType: "user", Details: map[string]any{"reason": "incorrect_current_password"}})
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
			"admin_ip", logIP(getClientIP(r), cfg),
		)
		recordAdmin(r, cfg, audit.Event{Type: models.AuditEventAuth, Action: "admin_password_change", Outcome: models.AuditOutcomeSuccess,
			ResourceType: "user"})

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
func AdminCleanupPartialUploadsHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
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
			"admin_ip", logIP(clientIP, cfg),
			"expiry_hours", expiryHours,
		)

		// Clean up abandoned uploads
		result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, expiryHours)
		if err != nil {
			slog.Error("failed to cleanup partial uploads",
				"error", err,
				"admin_ip", logIP(clientIP, cfg),
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
			"admin_ip", logIP(clientIP, cfg),
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
			"success":               true,
			"deleted_count":         result.DeletedCount,
			"abandoned_count":       result.AbandonedCount,
			"orphaned_chunks_count": result.OrphanedCount,
			"orphaned_files_count":  result.OrphanedFilesCount,
			"bytes_reclaimed":       result.BytesReclaimed,
			"orphaned_chunk_bytes":  result.OrphanedBytes,
			"orphaned_file_bytes":   result.OrphanedFilesBytes,
			"message":               message,
		})
	}
}
