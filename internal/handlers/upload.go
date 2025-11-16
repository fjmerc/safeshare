package handlers

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
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
		r.Body = http.MaxBytesReader(w, r.Body, cfg.GetMaxFileSize())
		if err := r.ParseMultipartForm(cfg.GetMaxFileSize()); err != nil {
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
		allowed, blockedExt, err := utils.IsFileAllowed(header.Filename, cfg.GetBlockedExtensions())
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
		if header.Size > cfg.GetMaxFileSize() {
			sendError(w, fmt.Sprintf("File size exceeds maximum of %d bytes", cfg.GetMaxFileSize()), "FILE_TOO_LARGE", http.StatusRequestEntityTooLarge)
			return
		}

		// Check disk space before accepting upload
		// Skip percentage check if quota is configured (quota takes precedence)
		quotaConfigured := cfg.GetQuotaLimitGB() > 0
		hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, header.Size, quotaConfigured)
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
		if quotaConfigured {
			currentUsage, err := database.GetTotalUsage(db)
			if err != nil {
				slog.Error("failed to get current storage usage", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			quotaBytes := cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024 // Convert GB to bytes
			if currentUsage+header.Size > quotaBytes {
				quotaUsedGB := float64(currentUsage) / (1024 * 1024 * 1024)
				slog.Warn("quota exceeded",
					"file_size", header.Size,
					"current_usage_gb", quotaUsedGB,
					"quota_limit_gb", cfg.GetQuotaLimitGB(),
					"client_ip", getClientIP(r),
				)
				sendError(w,
					fmt.Sprintf("Storage quota exceeded. Current usage: %.2f GB / %d GB", quotaUsedGB, cfg.GetQuotaLimitGB()),
					"QUOTA_EXCEEDED",
					http.StatusInsufficientStorage,
				)
				return
			}
		}

		// Parse optional parameters
		expiresInHours := cfg.GetDefaultExpirationHours()
		if hoursStr := r.FormValue("expires_in_hours"); hoursStr != "" {
			hours, err := strconv.ParseFloat(hoursStr, 64)
			if err != nil || hours <= 0 {
				sendError(w, "Invalid expires_in_hours parameter", "INVALID_PARAMETER", http.StatusBadRequest)
				return
			}

			// Validate against maximum expiration time (security: prevent disk space abuse)
			if int(hours) > cfg.GetMaxExpirationHours() {
				sendError(w,
					fmt.Sprintf("Expiration time exceeds maximum allowed (%d hours). Files that never expire waste disk space.", cfg.GetMaxExpirationHours()),
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
			expiresInHours = cfg.GetDefaultExpirationHours() * 60 // Convert to minutes
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

		// MIME type detection: Read first 512 bytes to detect file type without loading entire file into memory.
		// This buffer will be prepended back to the stream for processing.
		mimeBuffer := make([]byte, 512)
		n, err := io.ReadFull(file, mimeBuffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			slog.Error("failed to read file for MIME detection", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		// Handle files smaller than 512 bytes (n will be less than 512, err will be EOF or ErrUnexpectedEOF)
		mimeBuffer = mimeBuffer[:n]

		// Detect MIME type from file content (don't trust user-provided Content-Type)
		// This prevents attackers from uploading malicious files with fake MIME types
		mtype := mimetype.Detect(mimeBuffer)
		detectedMimeType := mtype.String()
		slog.Debug("MIME type detected",
			"filename", header.Filename,
			"detected", detectedMimeType,
			"user_provided", header.Header.Get("Content-Type"),
			"bytes_analyzed", n,
		)

		// Reconstruct full file stream by combining MIME buffer with remaining content
		fullReader := io.MultiReader(bytes.NewReader(mimeBuffer), file)

		// Compute SHA256 hash of original file (before encryption) using TeeReader
		// This allows us to hash the file as we stream it, with zero extra I/O
		hasher := sha256.New()
		hashedReader := io.TeeReader(fullReader, hasher)

		// Atomic write pattern: Write to temp file, then rename to final path
		// This prevents partial files on disk if upload/encryption fails mid-stream
		filePath := filepath.Join(cfg.UploadDir, storedFilename)
		tempPath := filePath + ".tmp"

		// Create temp file for atomic write
		tempFile, err := os.Create(tempPath)
		if err != nil {
			slog.Error("failed to create temp file", "path", tempPath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Track success for cleanup
		var succeeded bool
		defer func() {
			tempFile.Close()
			if !succeeded {
				// Clean up temp file if anything failed
				os.Remove(tempPath)
			}
		}()

		// Stream file to disk with optional encryption
		// This approach uses constant memory (~10MB) regardless of file size
		// The hashedReader computes SHA256 as we stream (zero extra I/O)
		var written int64
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			// Stream encrypt: Read chunks from upload → hash → encrypt → write to temp file
			// Uses SFSE1 format (compatible with existing decryption)
			err = utils.EncryptFileStreamingFromReader(tempFile, hashedReader, cfg.EncryptionKey)
			if err != nil {
				slog.Error("failed to encrypt file stream", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			written = header.Size // Use original size for storage accounting (not encrypted size)
			slog.Debug("file encrypted with streaming encryption",
				"original_size", header.Size,
				"filename", header.Filename,
			)
		} else {
			// Direct stream copy: Read from upload → hash → write to temp file
			written, err = io.Copy(tempFile, hashedReader)
			if err != nil {
				slog.Error("failed to write file stream", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			slog.Debug("file written without encryption", "size", written)
		}

		// Finalize SHA256 hash (computed during streaming above)
		sha256Hash := hex.EncodeToString(hasher.Sum(nil))

		// Close temp file before rename (required on Windows)
		if err := tempFile.Close(); err != nil {
			slog.Error("failed to close temp file", "path", tempPath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Atomic rename: Move temp file to final path
		// This is atomic on most filesystems (POSIX guarantees this)
		if err := os.Rename(tempPath, filePath); err != nil {
			slog.Error("failed to rename temp file", "temp", tempPath, "final", filePath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Mark success so defer doesn't delete temp file
		succeeded = true

		// Get client IP
		clientIP := getClientIP(r)

		// Get user ID if authenticated (optional)
		var userID *int64
		if user, ok := r.Context().Value("user").(*models.User); ok && user != nil {
			userID = &user.ID
		}

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
			UserID:           userID,
			SHA256Hash:       sha256Hash,
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

		// Record metrics
		metrics.UploadsTotal.WithLabelValues("success").Inc()
		metrics.UploadSizeBytes.Observe(float64(written))

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

// getClientIP extracts the client IP address from the request
