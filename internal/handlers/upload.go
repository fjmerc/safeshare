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
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
)

// uploadParams holds parsed upload request parameters
type uploadParams struct {
	expiresInMinutes int
	neverExpire      bool
	maxDownloads     *int
	passwordHash     string
}

// fileProcessingResult holds the result of file processing and storage
type fileProcessingResult struct {
	storedFilename   string
	filePath         string
	written          int64
	sha256Hash       string
	detectedMimeType string
}

// UploadHandler handles file upload requests
func UploadHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Validate and retrieve uploaded file
		file, header, err := validateAndGetUploadedFile(w, r, cfg)
		if err != nil {
			return // Error already sent to client
		}
		defer file.Close()

		// Check storage availability
		quotaConfigured := cfg.GetQuotaLimitGB() > 0
		if err := checkStorageAvailability(w, r, cfg, header.Size, quotaConfigured); err != nil {
			return // Error already sent to client
		}

		// Parse request parameters
		params, err := parseUploadParameters(w, r, cfg)
		if err != nil {
			return // Error already sent to client
		}

		// Generate unique claim code
		claimCode, err := generateUniqueClaimCode(w, db)
		if err != nil {
			return // Error already sent to client
		}

		// Process and store file
		result, err := processAndStoreFile(w, file, header, cfg)
		if err != nil {
			return // Error already sent to client
		}

		// Create database record and handle response
		createRecordAndRespond(w, r, db, cfg, header, params, claimCode, result, quotaConfigured)
	}
}

// validateAndGetUploadedFile validates the request and retrieves the uploaded file
func validateAndGetUploadedFile(w http.ResponseWriter, r *http.Request, cfg *config.Config) (multipart.File, *multipart.FileHeader, error) {
	// Parse multipart form with size limit
	r.Body = http.MaxBytesReader(w, r.Body, cfg.GetMaxFileSize())
	if err := r.ParseMultipartForm(cfg.GetMaxFileSize()); err != nil {
		sendError(w, "File too large or invalid form data", "FILE_TOO_LARGE", http.StatusRequestEntityTooLarge)
		return nil, nil, err
	}

	// Get the file from the form
	file, header, err := r.FormFile("file")
	if err != nil {
		sendError(w, "No file provided", "NO_FILE", http.StatusBadRequest)
		return nil, nil, err
	}

	// Validate file extension
	allowed, blockedExt, err := utils.IsFileAllowed(header.Filename, cfg.GetBlockedExtensions())
	if err != nil {
		slog.Error("failed to validate file extension", "error", err)
		sendError(w, "Invalid filename", "INVALID_FILENAME", http.StatusBadRequest)
		return nil, nil, err
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
		return nil, nil, fmt.Errorf("blocked extension: %s", blockedExt)
	}

	// Validate file size
	if header.Size > cfg.GetMaxFileSize() {
		sendError(w, fmt.Sprintf("File size exceeds maximum of %d bytes", cfg.GetMaxFileSize()), "FILE_TOO_LARGE", http.StatusRequestEntityTooLarge)
		return nil, nil, fmt.Errorf("file too large")
	}

	return file, header, nil
}

// checkStorageAvailability verifies there is sufficient storage space
func checkStorageAvailability(w http.ResponseWriter, r *http.Request, cfg *config.Config, fileSize int64, quotaConfigured bool) error {
	// Skip percentage check if quota is configured (quota takes precedence)
	hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, fileSize, quotaConfigured)
	if err != nil {
		slog.Error("failed to check disk space", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return err
	}
	if !hasSpace {
		slog.Warn("insufficient disk space",
			"file_size", fileSize,
			"client_ip", getClientIP(r),
			"reason", errMsg,
		)
		sendError(w, errMsg, "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
		return fmt.Errorf("insufficient storage")
	}
	return nil
}

// parseUploadParameters extracts and validates upload parameters from request
func parseUploadParameters(w http.ResponseWriter, r *http.Request, cfg *config.Config) (*uploadParams, error) {
	params := &uploadParams{
		expiresInMinutes: cfg.GetDefaultExpirationHours() * 60,
		neverExpire:      false,
	}

	// Parse expiration parameter
	if hoursStr := r.FormValue("expires_in_hours"); hoursStr != "" {
		hours, err := strconv.ParseFloat(hoursStr, 64)
		if err != nil || hours < 0 {
			sendError(w, "Invalid expires_in_hours parameter", "INVALID_PARAMETER", http.StatusBadRequest)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("negative expiration value")
		}

		if hours == 0 {
			params.neverExpire = true
		} else {
			if int(hours) > cfg.GetMaxExpirationHours() {
				sendError(w,
					fmt.Sprintf("Expiration time exceeds maximum allowed (%d hours). Use 0 for files that never expire.", cfg.GetMaxExpirationHours()),
					"EXPIRATION_TOO_LONG",
					http.StatusBadRequest,
				)
				return nil, fmt.Errorf("expiration too long")
			}
			params.expiresInMinutes = int(hours * 60)
			if params.expiresInMinutes < 1 {
				params.expiresInMinutes = 1
			}
		}
	}

	// Parse max downloads parameter
	if maxDownloadsStr := r.FormValue("max_downloads"); maxDownloadsStr != "" {
		maxDl, err := strconv.Atoi(maxDownloadsStr)
		if err != nil || maxDl <= 0 {
			sendError(w, "Invalid max_downloads parameter", "INVALID_PARAMETER", http.StatusBadRequest)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("invalid max_downloads value")
		}
		params.maxDownloads = &maxDl
	}

	// Parse password parameter
	if password := r.FormValue("password"); password != "" {
		hash, err := utils.HashPassword(password)
		if err != nil {
			slog.Error("failed to hash password", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return nil, err
		}
		params.passwordHash = hash
	}

	return params, nil
}

// generateUniqueClaimCode creates a unique claim code with retry logic
func generateUniqueClaimCode(w http.ResponseWriter, db *sql.DB) (string, error) {
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		claimCode, err := utils.GenerateClaimCode()
		if err != nil {
			slog.Error("failed to generate claim code", "error", err)
			sendError(w, "Failed to generate claim code", "INTERNAL_ERROR", http.StatusInternalServerError)
			return "", err
		}

		// Check if code already exists
		existing, err := database.GetFileByClaimCode(db, claimCode)
		if err != nil {
			slog.Error("failed to check claim code", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return "", err
		}

		if existing == nil {
			return claimCode, nil
		}

		if i == maxRetries-1 {
			sendError(w, "Failed to generate unique claim code", "INTERNAL_ERROR", http.StatusInternalServerError)
			return "", fmt.Errorf("failed to generate unique claim code")
		}
	}
	return "", fmt.Errorf("unreachable")
}

// processAndStoreFile handles MIME detection, streaming, hashing, and storage
func processAndStoreFile(w http.ResponseWriter, file multipart.File, header *multipart.FileHeader, cfg *config.Config) (*fileProcessingResult, error) {
	// Generate unique filename for storage
	storedFilename := uuid.New().String() + filepath.Ext(header.Filename)

	// Create upload directory if it doesn't exist
	if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
		slog.Error("failed to create upload directory", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return nil, err
	}

	// Detect MIME type from file content
	detectedMimeType, fullReader, err := detectMimeTypeAndCreateReader(w, file, header)
	if err != nil {
		return nil, err
	}

	// Stream file to disk with hashing and optional encryption
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	written, sha256Hash, err := streamFileToStorage(w, fullReader, header, filePath, cfg)
	if err != nil {
		return nil, err
	}

	return &fileProcessingResult{
		storedFilename:   storedFilename,
		filePath:         filePath,
		written:          written,
		sha256Hash:       sha256Hash,
		detectedMimeType: detectedMimeType,
	}, nil
}

// detectMimeTypeAndCreateReader detects MIME type and creates a reader for the full file
func detectMimeTypeAndCreateReader(w http.ResponseWriter, file multipart.File, header *multipart.FileHeader) (string, io.Reader, error) {
	// Read first 512 bytes for MIME detection
	mimeBuffer := make([]byte, 512)
	n, err := io.ReadFull(file, mimeBuffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		slog.Error("failed to read file for MIME detection", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return "", nil, err
	}
	mimeBuffer = mimeBuffer[:n]

	// Detect MIME type from file content
	mtype := mimetype.Detect(mimeBuffer)
	detectedMimeType := mtype.String()
	slog.Debug("MIME type detected",
		"filename", header.Filename,
		"detected", detectedMimeType,
		"user_provided", header.Header.Get("Content-Type"),
		"bytes_analyzed", n,
	)

	// Reconstruct full file stream
	fullReader := io.MultiReader(bytes.NewReader(mimeBuffer), file)
	return detectedMimeType, fullReader, nil
}

// streamFileToStorage streams file to disk with hashing and optional encryption
func streamFileToStorage(w http.ResponseWriter, reader io.Reader, header *multipart.FileHeader, filePath string, cfg *config.Config) (int64, string, error) {
	// Setup SHA256 hashing during streaming
	hasher := sha256.New()
	hashedReader := io.TeeReader(reader, hasher)

	// Atomic write pattern: temp file then rename
	tempPath := filePath + ".tmp"
	tempFile, err := os.Create(tempPath)
	if err != nil {
		slog.Error("failed to create temp file", "path", tempPath, "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return 0, "", err
	}

	// Track success for cleanup
	var succeeded bool
	defer func() {
		tempFile.Close()
		if !succeeded {
			os.Remove(tempPath)
		}
	}()

	// Stream file with optional encryption
	var written int64
	if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
		err = utils.EncryptFileStreamingFromReader(tempFile, hashedReader, cfg.EncryptionKey)
		if err != nil {
			slog.Error("failed to encrypt file stream", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return 0, "", err
		}
		written = header.Size
		slog.Debug("file encrypted with streaming encryption",
			"original_size", header.Size,
			"filename", header.Filename,
		)
	} else {
		written, err = io.Copy(tempFile, hashedReader)
		if err != nil {
			slog.Error("failed to write file stream", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return 0, "", err
		}
		slog.Debug("file written without encryption", "size", written)
	}

	// Finalize hash
	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	// Close and atomically rename
	if err := tempFile.Close(); err != nil {
		slog.Error("failed to close temp file", "path", tempPath, "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return 0, "", err
	}

	if err := os.Rename(tempPath, filePath); err != nil {
		slog.Error("failed to rename temp file", "temp", tempPath, "final", filePath, "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return 0, "", err
	}

	succeeded = true
	return written, sha256Hash, nil
}

// createRecordAndRespond creates database record and sends response
func createRecordAndRespond(w http.ResponseWriter, r *http.Request, db *sql.DB, cfg *config.Config, header *multipart.FileHeader, params *uploadParams, claimCode string, result *fileProcessingResult, quotaConfigured bool) {
	clientIP := getClientIP(r)

	// Get user ID if authenticated
	var userID *int64
	if user := middleware.GetUserFromContext(r); user != nil {
		userID = &user.ID
	}

	// Build file record
	sanitizedFilename := utils.SanitizeFilename(header.Filename)
	var expiresAt time.Time
	if params.neverExpire {
		expiresAt = time.Now().Add(time.Duration(100*365*24) * time.Hour)
	} else {
		expiresAt = time.Now().Add(time.Duration(params.expiresInMinutes) * time.Minute)
	}

	fileRecord := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: sanitizedFilename,
		StoredFilename:   result.storedFilename,
		FileSize:         result.written,
		MimeType:         result.detectedMimeType,
		ExpiresAt:        expiresAt,
		MaxDownloads:     params.maxDownloads,
		UploaderIP:       clientIP,
		PasswordHash:     params.passwordHash,
		UserID:           userID,
		SHA256Hash:       result.sha256Hash,
	}

	// Create database record with quota check if needed
	if err := createFileRecord(w, db, cfg, fileRecord, result.filePath, quotaConfigured, clientIP); err != nil {
		return
	}

	// Send success response and record metrics
	sendSuccessResponse(w, r, cfg, fileRecord, claimCode, result, sanitizedFilename, header, params.passwordHash, clientIP)
}

// createFileRecord creates the database record with optional quota check
func createFileRecord(w http.ResponseWriter, db *sql.DB, cfg *config.Config, fileRecord *models.File, filePath string, quotaConfigured bool, clientIP string) error {
	if quotaConfigured {
		quotaBytes := cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024
		if err := database.CreateFileWithQuotaCheck(db, fileRecord, quotaBytes); err != nil {
			os.Remove(filePath)
			if strings.Contains(err.Error(), "quota exceeded") {
				slog.Warn("quota exceeded (transactional check)",
					"file_size", fileRecord.FileSize,
					"quota_limit_gb", cfg.GetQuotaLimitGB(),
					"client_ip", clientIP,
				)
				sendError(w, "Storage quota exceeded", "QUOTA_EXCEEDED", http.StatusInsufficientStorage)
				return err
			}
			slog.Error("failed to create file record", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return err
		}
	} else {
		if err := database.CreateFile(db, fileRecord); err != nil {
			os.Remove(filePath)
			slog.Error("failed to create file record", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return err
		}
	}
	return nil
}

// sendSuccessResponse sends the upload success response and records metrics
func sendSuccessResponse(w http.ResponseWriter, r *http.Request, cfg *config.Config, fileRecord *models.File, claimCode string, result *fileProcessingResult, sanitizedFilename string, header *multipart.FileHeader, passwordHash string, clientIP string) {
	downloadURL := buildDownloadURL(r, cfg, claimCode)

	response := models.UploadResponse{
		ClaimCode:          claimCode,
		ExpiresAt:          fileRecord.ExpiresAt,
		DownloadURL:        downloadURL,
		MaxDownloads:       fileRecord.MaxDownloads,
		CompletedDownloads: 0,
		FileSize:           result.written,
		OriginalFilename:   sanitizedFilename,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

	// Record metrics
	metrics.UploadsTotal.WithLabelValues("success").Inc()
	metrics.UploadSizeBytes.Observe(float64(result.written))

	// Emit webhook event
	EmitWebhookEvent(&webhooks.Event{
		Type:      webhooks.EventFileUploaded,
		Timestamp: time.Now(),
		File: webhooks.FileData{
			ID:        fileRecord.ID,
			ClaimCode: claimCode,
			Filename:  sanitizedFilename,
			Size:      result.written,
			MimeType:  result.detectedMimeType,
			ExpiresAt: fileRecord.ExpiresAt,
		},
	})

	slog.Info("file uploaded",
		"claim_code", redactClaimCode(claimCode),
		"filename", header.Filename,
		"file_extension", utils.GetFileExtension(header.Filename),
		"size", result.written,
		"expires_at", fileRecord.ExpiresAt,
		"max_downloads", fileRecord.MaxDownloads,
		"password_protected", passwordHash != "",
		"client_ip", clientIP,
		"user_agent", getUserAgent(r),
	)
}

// getClientIP extracts the client IP address from the request
