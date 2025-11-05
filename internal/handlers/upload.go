package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
	"github.com/yourusername/safeshare/internal/config"
	"github.com/yourusername/safeshare/internal/database"
	"github.com/yourusername/safeshare/internal/models"
	"github.com/yourusername/safeshare/internal/utils"
)

// UploadHandler handles file upload requests
func UploadHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Parse multipart form with size limit
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxFileSize)
		if err := r.ParseMultipartForm(cfg.MaxFileSize); err != nil {
			sendError(w, "File too large or invalid form data", "FILE_TOO_LARGE", http.StatusRequestEntityTooLarge)
			return
		}

		// Get the file from the form
		file, header, err := r.FormFile("file")
		if err != nil {
			sendError(w, "No file provided", "NO_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Validate file extension
		allowed, blockedExt, err := utils.IsFileAllowed(header.Filename, cfg.BlockedExtensions)
		if err != nil {
			slog.Error("failed to validate file extension", "error", err)
			sendError(w, "Invalid filename", "INVALID_FILENAME", http.StatusBadRequest)
			return
		}
		if !allowed {
			clientIP := getClientIP(r)
			slog.Warn("blocked file extension",
				"filename", header.Filename,
				"extension", blockedExt,
				"client_ip", clientIP,
			)
			sendError(w,
				fmt.Sprintf("File extension '%s' is not allowed for security reasons", blockedExt),
				"BLOCKED_EXTENSION",
				http.StatusBadRequest,
			)
			return
		}

		// Validate file size
		if header.Size > cfg.MaxFileSize {
			sendError(w, fmt.Sprintf("File size exceeds maximum of %d bytes", cfg.MaxFileSize), "FILE_TOO_LARGE", http.StatusRequestEntityTooLarge)
			return
		}

		// Check disk space before accepting upload
		hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, header.Size)
		if err != nil {
			slog.Error("failed to check disk space", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !hasSpace {
			slog.Warn("insufficient disk space",
				"file_size", header.Size,
				"client_ip", getClientIP(r),
				"reason", errMsg,
			)
			sendError(w, errMsg, "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
			return
		}

		// Check quota if configured (0 = unlimited)
		if cfg.QuotaLimitGB > 0 {
			currentUsage, err := database.GetTotalUsage(db)
			if err != nil {
				slog.Error("failed to get current storage usage", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			quotaBytes := cfg.QuotaLimitGB * 1024 * 1024 * 1024 // Convert GB to bytes
			if currentUsage+header.Size > quotaBytes {
				quotaUsedGB := float64(currentUsage) / (1024 * 1024 * 1024)
				slog.Warn("quota exceeded",
					"file_size", header.Size,
					"current_usage_gb", quotaUsedGB,
					"quota_limit_gb", cfg.QuotaLimitGB,
					"client_ip", getClientIP(r),
				)
				sendError(w,
					fmt.Sprintf("Storage quota exceeded. Current usage: %.2f GB / %d GB", quotaUsedGB, cfg.QuotaLimitGB),
					"QUOTA_EXCEEDED",
					http.StatusInsufficientStorage,
				)
				return
			}
		}

		// Parse optional parameters
		expiresInHours := cfg.DefaultExpirationHours
		if hoursStr := r.FormValue("expires_in_hours"); hoursStr != "" {
			hours, err := strconv.ParseFloat(hoursStr, 64)
			if err != nil || hours <= 0 {
				sendError(w, "Invalid expires_in_hours parameter", "INVALID_PARAMETER", http.StatusBadRequest)
				return
			}

			// Validate against maximum expiration time (security: prevent disk space abuse)
			if int(hours) > cfg.MaxExpirationHours {
				sendError(w,
					fmt.Sprintf("Expiration time exceeds maximum allowed (%d hours). Files that never expire waste disk space.", cfg.MaxExpirationHours),
					"EXPIRATION_TOO_LONG",
					http.StatusBadRequest,
				)
				return
			}

			expiresInHours = int(hours * 60) // Convert to minutes for precision
			if expiresInHours < 1 {
				expiresInHours = 1 // Minimum 1 minute
			}
		} else {
			expiresInHours = cfg.DefaultExpirationHours * 60 // Convert to minutes
		}

		var maxDownloads *int
		if maxDownloadsStr := r.FormValue("max_downloads"); maxDownloadsStr != "" {
			maxDl, err := strconv.Atoi(maxDownloadsStr)
			if err != nil || maxDl <= 0 {
				sendError(w, "Invalid max_downloads parameter", "INVALID_PARAMETER", http.StatusBadRequest)
				return
			}
			maxDownloads = &maxDl
		}

	// Parse optional password for password protection
	var passwordHash string
	if password := r.FormValue("password"); password != "" {
		hash, err := utils.HashPassword(password)
		if err != nil {
			slog.Error("failed to hash password", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		passwordHash = hash
	}

		// Generate unique claim code (with retry on collision)
		var claimCode string
		maxRetries := 5
		for i := 0; i < maxRetries; i++ {
			claimCode, err = utils.GenerateClaimCode()
			if err != nil {
				slog.Error("failed to generate claim code", "error", err)
				sendError(w, "Failed to generate claim code", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			// Check if code already exists
			existing, err := database.GetFileByClaimCode(db, claimCode)
			if err != nil {
				slog.Error("failed to check claim code", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			if existing == nil {
				break // Code is unique
			}

			if i == maxRetries-1 {
				sendError(w, "Failed to generate unique claim code", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
		}

		// Generate unique filename for storage
		storedFilename := uuid.New().String() + filepath.Ext(header.Filename)

		// Create upload directory if it doesn't exist
		if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
			slog.Error("failed to create upload directory", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Read file content into memory (safe for configured max file size)
		fileContent, err := io.ReadAll(file)
		if err != nil {
			slog.Error("failed to read uploaded file", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Detect MIME type from file content (don't trust user-provided Content-Type)
		// This prevents attackers from uploading malicious files with fake MIME types
		mtype := mimetype.Detect(fileContent)
		detectedMimeType := mtype.String()
		slog.Debug("MIME type detected",
			"filename", header.Filename,
			"detected", detectedMimeType,
			"user_provided", header.Header.Get("Content-Type"),
		)

		// Encrypt if encryption is enabled
		var dataToWrite []byte
		var written int64
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			encrypted, err := utils.EncryptFile(fileContent, cfg.EncryptionKey)
			if err != nil {
				slog.Error("failed to encrypt file", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			dataToWrite = encrypted
			written = int64(len(fileContent)) // Use original size for storage accounting
			slog.Debug("file encrypted", "original_size", len(fileContent), "encrypted_size", len(encrypted))
		} else {
			dataToWrite = fileContent
			written = int64(len(fileContent))
		}

		// Save file to disk
		filePath := filepath.Join(cfg.UploadDir, storedFilename)
		if err := os.WriteFile(filePath, dataToWrite, 0644); err != nil {
			slog.Error("failed to write file", "path", filePath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Get client IP
		clientIP := getClientIP(r)

		// Create database record
		// Sanitize original filename to prevent log injection and display issues
		sanitizedFilename := utils.SanitizeFilename(header.Filename)
		expiresAt := time.Now().Add(time.Duration(expiresInHours) * time.Minute)
		fileRecord := &models.File{
			ClaimCode:        claimCode,
			OriginalFilename: sanitizedFilename,
			StoredFilename:   storedFilename,
			FileSize:         written,
			MimeType:         detectedMimeType, // Use detected MIME type, not user-provided
			ExpiresAt:        expiresAt,
			MaxDownloads:     maxDownloads,
			UploaderIP:       clientIP,
		PasswordHash:     passwordHash,
		}

		if err := database.CreateFile(db, fileRecord); err != nil {
			os.Remove(filePath) // Clean up on error
			slog.Error("failed to create file record", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Build download URL (respects reverse proxy headers and PUBLIC_URL config)
		downloadURL := buildDownloadURL(r, cfg, claimCode)

		// Send success response
		response := models.UploadResponse{
			ClaimCode:        claimCode,
			ExpiresAt:        expiresAt,
			DownloadURL:      downloadURL,
			MaxDownloads:     maxDownloads,
			FileSize:         written,
			OriginalFilename: sanitizedFilename,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)

		slog.Info("file uploaded",
			"claim_code", redactClaimCode(claimCode),
			"filename", header.Filename,
			"file_extension", utils.GetFileExtension(header.Filename),
			"size", written,
			"expires_at", expiresAt,
			"max_downloads", maxDownloads,
		"password_protected", passwordHash != "",
			"client_ip", clientIP,
			"user_agent", getUserAgent(r),
		)
	}
}

// sendError sends a JSON error response
func sendError(w http.ResponseWriter, message, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	errResp := models.ErrorResponse{
		Error: message,
		Code:  code,
	}

	json.NewEncoder(w).Encode(errResp)
}

// getClientIP extracts the client IP address from the request
