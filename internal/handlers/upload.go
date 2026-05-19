package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/scanning"
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
	clientEncrypted  bool
}

// fileProcessingResult holds the result of file processing and storage
type fileProcessingResult struct {
	storedFilename   string
	filePath         string
	written          int64
	sha256Hash       string
	detectedMimeType string
	encFileID        []byte // 16-byte SFSE2 file identity (nil when encryption disabled or legacy SFSE1 path used)
}

// UploadHandler handles file upload requests
func UploadHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// Only accept POST requests
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Check if server is shutting down
		uploadTracker := utils.GetUploadTracker()
		if uploadTracker.IsShuttingDown() {
			sendError(w, "Server is shutting down, not accepting new uploads", "SERVICE_UNAVAILABLE", http.StatusServiceUnavailable)
			return
		}

		// Validate and retrieve uploaded file
		file, header, err := validateAndGetUploadedFile(w, r, cfg)
		if err != nil {
			return // Error already sent to client
		}
		defer file.Close()

		// Track this upload for graceful shutdown
		uploadID := uuid.New().String()
		if !uploadTracker.StartUpload(uploadID, header.Filename, header.Size) {
			sendError(w, "Server is shutting down, not accepting new uploads", "SERVICE_UNAVAILABLE", http.StatusServiceUnavailable)
			return
		}
		defer uploadTracker.FinishUpload(uploadID)

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
		claimCode, err := generateUniqueClaimCode(ctx, w, repos)
		if err != nil {
			return // Error already sent to client
		}

		// Process and store file
		result, err := processAndStoreFile(w, file, header, cfg)
		if err != nil {
			return // Error already sent to client
		}

		// Strip metadata if enabled and supported
		if cfg.IsStripMetadata() && privacy.SupportsMetadataStripping(result.detectedMimeType) {
			if err := stripMetadataFromUpload(result, cfg); err != nil {
				slog.Warn("failed to strip metadata",
					"error", err,
					"filename", header.Filename,
					"mime_type", result.detectedMimeType,
				)
				// Non-fatal: continue with original file
			}
		}

		// Create database record and handle response
		createRecordAndRespond(ctx, w, r, repos, cfg, header, params, claimCode, result, quotaConfigured)
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

	// Validate filename for control characters (header injection prevention)
	if err := utils.ValidateUploadFilename(header.Filename); err != nil {
		clientIP := getClientIP(r)
		slog.Warn("rejected filename with control characters",
			"filename", header.Filename,
			"error", err,
			"client_ip", clientIP,
		)
		sendError(w, "Invalid filename", "INVALID_FILENAME", http.StatusBadRequest)
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
			"client_ip", logIP(clientIP, cfg),
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
			"client_ip", logIP(getClientIP(r), cfg),
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

	// Parse client_encrypted flag (E2E indicator). Untrusted; affects display only.
	if v := r.FormValue("client_encrypted"); v == "true" || v == "1" {
		params.clientEncrypted = true
	}

	return params, nil
}

// generateUniqueClaimCode creates a unique claim code with retry logic
func generateUniqueClaimCode(ctx context.Context, w http.ResponseWriter, repos *repository.Repositories) (string, error) {
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		claimCode, err := utils.GenerateClaimCode()
		if err != nil {
			slog.Error("failed to generate claim code", "error", err)
			sendError(w, "Failed to generate claim code", "INTERNAL_ERROR", http.StatusInternalServerError)
			return "", err
		}

		// Check if code already exists
		existing, err := repos.Files.GetByClaimCode(ctx, claimCode)
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
	written, sha256Hash, encFileID, err := streamFileToStorage(w, fullReader, header, filePath, cfg)
	if err != nil {
		return nil, err
	}

	return &fileProcessingResult{
		storedFilename:   storedFilename,
		filePath:         filePath,
		written:          written,
		sha256Hash:       sha256Hash,
		detectedMimeType: detectedMimeType,
		encFileID:        encFileID,
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

// streamFileToStorage streams file to disk with hashing and optional encryption.
// Returns (written, sha256Hash, encFileID, err). encFileID is non-nil and 16 bytes
// when encryption is enabled (SFSE2); nil when encryption is disabled.
func streamFileToStorage(w http.ResponseWriter, reader io.Reader, header *multipart.FileHeader, filePath string, cfg *config.Config) (int64, string, []byte, error) {
	// Setup SHA256 hashing during streaming
	hasher := sha256.New()
	hashedReader := io.TeeReader(reader, hasher)

	// Atomic write pattern: temp file then rename
	tempPath := filePath + ".tmp"
	tempFile, err := os.Create(tempPath)
	if err != nil {
		slog.Error("failed to create temp file", "path", tempPath, "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return 0, "", nil, err
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
	var encFileID []byte
	if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
		encFileID, err = utils.GenerateEncFileID()
		if err != nil {
			slog.Error("failed to generate enc_file_id", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return 0, "", nil, err
		}
		err = utils.EncryptFileStreamingV2FromReader(tempFile, hashedReader, cfg.EncryptionKey, encFileID, header.Size)
		if err != nil {
			slog.Error("failed to encrypt file stream (SFSE2)", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return 0, "", nil, err
		}
		written = header.Size
		slog.Debug("file encrypted with SFSE2 streaming encryption",
			"original_size", header.Size,
			"filename", header.Filename,
		)
	} else {
		written, err = io.Copy(tempFile, hashedReader)
		if err != nil {
			slog.Error("failed to write file stream", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return 0, "", nil, err
		}
		slog.Debug("file written without encryption", "size", written)
	}

	// Finalize hash
	sha256Hash := hex.EncodeToString(hasher.Sum(nil))

	// Close and atomically rename
	if err := tempFile.Close(); err != nil {
		slog.Error("failed to close temp file", "path", tempPath, "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return 0, "", nil, err
	}

	if err := os.Rename(tempPath, filePath); err != nil {
		slog.Error("failed to rename temp file", "temp", tempPath, "final", filePath, "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return 0, "", nil, err
	}

	succeeded = true
	return written, sha256Hash, encFileID, nil
}

// createRecordAndRespond creates database record and sends response
func createRecordAndRespond(ctx context.Context, w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, header *multipart.FileHeader, params *uploadParams, claimCode string, result *fileProcessingResult, quotaConfigured bool) {
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
		UploaderIP:       storeIP(clientIP, cfg),
		PasswordHash:     params.passwordHash,
		UserID:           userID,
		SHA256Hash:       result.sha256Hash,
		ClientEncrypted:  params.clientEncrypted,
		EncFileID:        result.encFileID,
	}

	// Create database record with quota check if needed
	if err := createFileRecord(ctx, w, repos, cfg, fileRecord, result.filePath, quotaConfigured, clientIP); err != nil {
		return
	}

	// Send success response and record metrics
	sendSuccessResponse(w, r, cfg, fileRecord, claimCode, result, sanitizedFilename, header, params.passwordHash, clientIP, repos)
}

// createFileRecord creates the database record with optional quota check
func createFileRecord(ctx context.Context, w http.ResponseWriter, repos *repository.Repositories, cfg *config.Config, fileRecord *models.File, filePath string, quotaConfigured bool, clientIP string) error {
	if quotaConfigured {
		quotaBytes := cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024
		if err := repos.Files.CreateWithQuotaCheck(ctx, fileRecord, quotaBytes); err != nil {
			os.Remove(filePath)
			if err == repository.ErrQuotaExceeded || strings.Contains(err.Error(), "quota exceeded") {
				slog.Warn("quota exceeded (transactional check)",
					"file_size", fileRecord.FileSize,
					"quota_limit_gb", cfg.GetQuotaLimitGB(),
					"client_ip", logIP(clientIP, cfg),
				)
				sendError(w, "Storage quota exceeded", "QUOTA_EXCEEDED", http.StatusInsufficientStorage)
				return err
			}
			slog.Error("failed to create file record", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return err
		}
	} else {
		if err := repos.Files.Create(ctx, fileRecord); err != nil {
			os.Remove(filePath)
			slog.Error("failed to create file record", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return err
		}
	}
	return nil
}

// sendSuccessResponse sends the upload success response, records metrics, and triggers async scanning.
func sendSuccessResponse(w http.ResponseWriter, r *http.Request, cfg *config.Config, fileRecord *models.File, claimCode string, result *fileProcessingResult, sanitizedFilename string, header *multipart.FileHeader, passwordHash string, clientIP string, repos *repository.Repositories) {
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

	// Trigger async malware scan (no-op if feature is disabled)
	triggerAsyncScan(fileRecord.ID, result.filePath, claimCode, sanitizedFilename, result.written, result.detectedMimeType, fileRecord.ExpiresAt, cfg, repos)

	slog.Info("file uploaded",
		"claim_code", redactClaimCode(claimCode),
		"filename", header.Filename,
		"file_extension", utils.GetFileExtension(header.Filename),
		"size", result.written,
		"expires_at", fileRecord.ExpiresAt,
		"max_downloads", fileRecord.MaxDownloads,
		"password_protected", passwordHash != "",
		"client_ip", logIP(clientIP, cfg),
		"user_agent", getUserAgent(r),
	)
}

// stripMetadataFromUpload strips metadata from an uploaded file and updates the result.
// Handles both encrypted and unencrypted files.
func stripMetadataFromUpload(result *fileProcessingResult, cfg *config.Config) error {
	encrypted := utils.IsEncryptionEnabled(cfg.EncryptionKey)

	if encrypted {
		return stripMetadataEncrypted(result, cfg)
	}
	return stripMetadataPlaintext(result)
}

// stripMetadataPlaintext strips metadata from an unencrypted file in-place,
// then recomputes the file size and SHA256 hash.
func stripMetadataPlaintext(result *fileProcessingResult) error {
	if err := privacy.StripFileMetadata(result.filePath, result.detectedMimeType); err != nil {
		return fmt.Errorf("strip metadata: %w", err)
	}

	// Recompute file size
	info, err := os.Stat(result.filePath)
	if err != nil {
		return fmt.Errorf("stat after stripping: %w", err)
	}
	result.written = info.Size()

	// Recompute SHA256 hash
	hash, err := computeFileHash(result.filePath)
	if err != nil {
		return fmt.Errorf("hash after stripping: %w", err)
	}
	result.sha256Hash = hash

	slog.Info("metadata stripped from upload",
		"mime_type", result.detectedMimeType,
		"file_size", result.written,
	)
	return nil
}

// stripMetadataEncrypted handles stripping for encrypted files:
// decrypt to OS temp dir → strip → re-encrypt to temp → atomic rename.
// The original encrypted file is preserved until re-encryption fully succeeds.
//
// The newly stripped file is re-emitted as SFSE2 — the re-encrypted file uses
// the same enc_file_id as the original (preserves AAD identity for the same
// logical file). For legacy V1 uploads that have an empty encFileID, a fresh
// one is generated here so the re-encrypted output is always SFSE2; the
// caller (createFileRecord) then persists it on the new DB row.
func stripMetadataEncrypted(result *fileProcessingResult, cfg *config.Config) error {
	// Decrypt to OS temp directory (not uploads dir) to avoid plaintext exposure
	tempFile, err := os.CreateTemp("", "safeshare-strip-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	tempFile.Close()
	defer os.Remove(tempPath)

	// Use the version-aware dispatcher; the file may be V1 (e.g. legacy data
	// in the uploads dir from before SFSE2 landed) or V2 (the path this
	// commit emits). Empty encFileID is safe for the V1 branch.
	// result.written is the plaintext length recorded at upload time; passing
	// it lets the V2 reader reject a header-length forgery before any AAD work.
	if err := utils.DecryptFileStreamingAny(result.filePath, tempPath, cfg.EncryptionKey, result.encFileID, "", result.written); err != nil {
		return fmt.Errorf("decrypt for stripping: %w", err)
	}

	// Strip metadata from decrypted temp file
	if err := privacy.StripFileMetadata(tempPath, result.detectedMimeType); err != nil {
		return fmt.Errorf("strip metadata (encrypted): %w", err)
	}

	// Compute hash from stripped plaintext
	hash, err := computeFileHash(tempPath)
	if err != nil {
		return fmt.Errorf("hash stripped plaintext: %w", err)
	}

	// Get stripped plaintext size (stored in DB as the user-facing file size)
	info, err := os.Stat(tempPath)
	if err != nil {
		return fmt.Errorf("stat stripped plaintext: %w", err)
	}

	// If we are stripping a legacy V1 upload, mint a fresh enc_file_id so the
	// re-encrypted output is SFSE2 (forward-only upgrade).
	encFileID := result.encFileID
	if len(encFileID) == 0 {
		encFileID, err = utils.GenerateEncFileID()
		if err != nil {
			return fmt.Errorf("generate enc_file_id for re-encrypt: %w", err)
		}
	}

	// Re-encrypt to a temp file next to the original, then atomic rename.
	// This preserves the original encrypted file until re-encryption succeeds.
	reencryptPath := result.filePath + ".reenc-tmp"
	if err := utils.EncryptFileStreamingV2(tempPath, reencryptPath, cfg.EncryptionKey, encFileID); err != nil {
		os.Remove(reencryptPath)
		return fmt.Errorf("re-encrypt after stripping: %w", err)
	}

	// Atomic replace — original file is preserved until this succeeds
	if err := os.Rename(reencryptPath, result.filePath); err != nil {
		os.Remove(reencryptPath)
		return fmt.Errorf("rename re-encrypted file: %w", err)
	}

	result.sha256Hash = hash
	result.written = info.Size()
	result.encFileID = encFileID

	slog.Info("metadata stripped from encrypted upload",
		"mime_type", result.detectedMimeType,
		"file_size", result.written,
	)
	return nil
}

// computeFileHash computes the SHA256 hash of a file.
func computeFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// triggerAsyncScan starts a background malware scan if the feature is enabled.
// It runs in a separate goroutine so it does not block the upload response.
func triggerAsyncScan(fileID int64, filePath string, claimCode string, filename string, fileSize int64, mimeType string, expiresAt time.Time, cfg *config.Config, repos *repository.Repositories) {
	if !cfg.Features.IsMalwareScanEnabled() {
		return
	}

	// Set initial scan status to pending before launching the goroutine so
	// the DB reflects the intent even if the goroutine has not yet started.
	ctx := context.Background()
	if err := repos.Files.UpdateScanStatus(ctx, fileID, scanning.ScanStatusPending, ""); err != nil {
		slog.Error("failed to set scan status to pending", "error", err, "file_id", fileID)
		return
	}

	go func() {
		scanner := scanning.NewClamAVScanner(
			cfg.ClamAV.Host,
			cfg.ClamAV.Port,
			time.Duration(cfg.ClamAV.Timeout)*time.Second,
			cfg.ClamAV.MaxFileSize,
		)

		result, err := scanner.ScanFile(filePath)
		if err != nil {
			slog.Error("malware scan failed",
				"error", err,
				"file_id", fileID,
				"claim_code", redactClaimCode(claimCode),
			)
			if updateErr := repos.Files.UpdateScanStatus(ctx, fileID, scanning.ScanStatusError, err.Error()); updateErr != nil {
				slog.Error("failed to update scan status", "error", updateErr, "file_id", fileID)
			}
			return
		}

		if result.Infected {
			slog.Warn("malware detected in uploaded file",
				"virus_name", result.VirusName,
				"file_id", fileID,
				"claim_code", redactClaimCode(claimCode),
				"scan_duration", result.Duration,
			)

			// Update status to infected
			if updateErr := repos.Files.UpdateScanStatus(ctx, fileID, scanning.ScanStatusInfected, result.VirusName); updateErr != nil {
				slog.Error("failed to update scan status", "error", updateErr, "file_id", fileID)
			}

			// Emit webhook
			scanStatus := scanning.ScanStatusInfected
			virusName := result.VirusName
			EmitWebhookEvent(&webhooks.Event{
				Type:      webhooks.EventFileInfected,
				Timestamp: time.Now(),
				File: webhooks.FileData{
					ID:         fileID,
					ClaimCode:  claimCode,
					Filename:   filename,
					Size:       fileSize,
					MimeType:   mimeType,
					ExpiresAt:  expiresAt,
					ScanStatus: &scanStatus,
					ScanResult: &virusName,
				},
			})

			// Delete the infected file from disk
			if err := os.Remove(filePath); err != nil {
				slog.Error("failed to remove infected file", "error", err, "file_id", fileID)
			}
			return
		}

		// File is clean
		slog.Info("malware scan completed: clean",
			"file_id", fileID,
			"claim_code", redactClaimCode(claimCode),
			"scan_duration", result.Duration,
		)
		if updateErr := repos.Files.UpdateScanStatus(ctx, fileID, scanning.ScanStatusClean, ""); updateErr != nil {
			slog.Error("failed to update scan status", "error", updateErr, "file_id", fileID)
		}
	}()
}
