package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/google/uuid"
)

// assemblySemaphore limits concurrent assembly workers to prevent memory exhaustion
// Each assembly uses a 20MB buffer, so 10 concurrent = 200MB max
var assemblySemaphore = make(chan struct{}, 10)

// UploadInitHandler handles POST /api/upload/init - Initialize chunked upload session
func UploadInitHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Check if chunked uploads are enabled
		if !cfg.ChunkedUploadEnabled {
			sendError(w, "Chunked uploads are disabled", "FEATURE_DISABLED", http.StatusServiceUnavailable)
			return
		}

		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

		// Parse JSON request body
		var req models.UploadInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendError(w, "Invalid JSON request body", "INVALID_JSON", http.StatusBadRequest)
			return
		}

		// Validate filename
		if req.Filename == "" {
			sendError(w, "Filename is required", "MISSING_FILENAME", http.StatusBadRequest)
			return
		}

		// Sanitize filename
		req.Filename = utils.SanitizeFilename(req.Filename)

		// Validate file extension
		allowed, blockedExt, err := utils.IsFileAllowed(req.Filename, cfg.GetBlockedExtensions())
		if err != nil {
			slog.Error("failed to validate file extension", "error", err)
			sendError(w, "Invalid filename", "INVALID_FILENAME", http.StatusBadRequest)
			return
		}
		if !allowed {
			clientIP := getClientIP(r)
			slog.Warn("blocked file extension during chunked upload init",
				"filename", req.Filename,
				"extension", blockedExt,
				"client_ip", clientIP,
			)
			sendSmartError(w,
				fmt.Sprintf("File extension '%s' is not allowed for security reasons", blockedExt),
				"BLOCKED_EXTENSION",
				http.StatusBadRequest,
			)
			return
		}

		// Validate total_size
		if req.TotalSize <= 0 {
			sendError(w, "Total size must be positive", "INVALID_TOTAL_SIZE", http.StatusBadRequest)
			return
		}

		// Check against MAX_FILE_SIZE
		if req.TotalSize > cfg.GetMaxFileSize() {
			sendSmartError(w,
				fmt.Sprintf("File size exceeds maximum of %d bytes", cfg.GetMaxFileSize()),
				"FILE_TOO_LARGE",
				http.StatusRequestEntityTooLarge,
			)
			return
		}

		// Calculate optimal chunk size based on file size
		// Falls back to configured chunk size if dynamic sizing is disabled
		chunkSize := utils.CalculateOptimalChunkSize(req.TotalSize)

		// Calculate total chunks using optimal chunk size (P1 security fix: prevent integer overflow)
		// Use int64 for calculation to prevent overflow on 32-bit systems
		totalChunks64 := req.TotalSize / chunkSize
		if req.TotalSize%chunkSize != 0 {
			totalChunks64++
		}

		// Validate total chunks BEFORE converting to int (prevent overflow bypass)
		if totalChunks64 > 10000 {
			sendSmartError(w,
				"File requires too many chunks (maximum 10,000). Try increasing chunk size.",
				"TOO_MANY_CHUNKS",
				http.StatusBadRequest,
			)
			return
		}

		// Safe to convert to int after validation
		totalChunks := int(totalChunks64)

		slog.Debug("calculated chunk parameters",
			"file_size", req.TotalSize,
			"chunk_size", chunkSize,
			"total_chunks", totalChunks,
		)

		// Validate expiration hours
		// Special case: 0 means "never expire", negative values use default
		if req.ExpiresInHours < 0 {
			req.ExpiresInHours = cfg.GetDefaultExpirationHours()
		}

		if req.ExpiresInHours > 0 && req.ExpiresInHours > cfg.GetMaxExpirationHours() {
			sendSmartError(w,
				fmt.Sprintf("Expiration time exceeds maximum allowed (%d hours). Use 0 for files that never expire.", cfg.GetMaxExpirationHours()),
				"EXPIRATION_TOO_LONG",
				http.StatusBadRequest,
			)
			return
		}

		// Validate max downloads (0 = unlimited, negative = invalid)
		if req.MaxDownloads < 0 {
			req.MaxDownloads = 0 // Default to unlimited
		}

		// Check disk space before accepting upload
		// Skip percentage check if quota is configured (quota takes precedence)
		quotaConfigured := cfg.GetQuotaLimitGB() > 0
		hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, req.TotalSize, quotaConfigured)
		if err != nil {
			slog.Error("failed to check disk space", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !hasSpace {
			slog.Warn("insufficient disk space for chunked upload init",
				"file_size", req.TotalSize,
				"client_ip", getClientIP(r),
				"reason", errMsg,
			)
			sendSmartError(w, errMsg, "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
			return
		}

		// Note: Quota check moved to transactional CreatePartialUploadWithQuotaCheck() to prevent race conditions

		// Hash password if provided
		var passwordHash string
		if req.Password != "" {
			hash, err := utils.HashPassword(req.Password)
			if err != nil {
				slog.Error("failed to hash password", "error", err)
				sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			passwordHash = hash
		}

		// Get user ID if authenticated
		var userID *int64
		if user := middleware.GetUserFromContext(r); user != nil {
			userID = &user.ID
		}

		// Generate upload ID (UUID)
		uploadID := uuid.New().String()

		// Create partial upload record
		partialUpload := &models.PartialUpload{
			UploadID:       uploadID,
			UserID:         userID,
			Filename:       req.Filename,
			TotalSize:      req.TotalSize,
			ChunkSize:      chunkSize, // Use calculated chunk size, not config default
			TotalChunks:    totalChunks,
			ChunksReceived: 0,
			ReceivedBytes:  0,
			ExpiresInHours: req.ExpiresInHours,
			MaxDownloads:   req.MaxDownloads,
			PasswordHash:   passwordHash,
			CreatedAt:      time.Now(),
			LastActivity:   time.Now(),
			Completed:      false,
			ClaimCode:      nil,
		}

		// Use transactional quota check to prevent race conditions (P0 fix)
		if quotaConfigured {
			quotaBytes := cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024
			if err := database.CreatePartialUploadWithQuotaCheck(db, partialUpload, quotaBytes); err != nil {
				if strings.Contains(err.Error(), "quota exceeded") {
					slog.Warn("quota exceeded for chunked upload (transactional check)",
						"file_size", req.TotalSize,
						"quota_limit_gb", cfg.GetQuotaLimitGB(),
						"client_ip", getClientIP(r),
					)
					sendSmartError(w, "Storage quota exceeded", "QUOTA_EXCEEDED", http.StatusInsufficientStorage)
					return
				}
				slog.Error("failed to create partial upload", "error", err)
				sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
		} else {
			// No quota configured - use regular CreatePartialUpload
			if err := database.CreatePartialUpload(db, partialUpload); err != nil {
				slog.Error("failed to create partial upload", "error", err)
				sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
		}

		// Calculate expiration time
		expiresAt := time.Now().Add(time.Duration(cfg.PartialUploadExpiryHours) * time.Hour)

		// Send response
		response := models.UploadInitResponse{
			UploadID:    uploadID,
			ChunkSize:   chunkSize, // Return actual chunk size to client
			TotalChunks: totalChunks,
			ExpiresAt:   expiresAt,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)

		// Record metrics
		metrics.ChunkedUploadsTotal.Inc()

		slog.Info("chunked upload initialized",
			"upload_id", uploadID,
			"filename", req.Filename,
			"total_size", req.TotalSize,
			"chunk_size", cfg.ChunkSize,
			"total_chunks", totalChunks,
			"expires_in_hours", req.ExpiresInHours,
			"password_protected", passwordHash != "",
			"client_ip", getClientIP(r),
		)
	}
}

// UploadChunkHandler handles POST /api/upload/chunk/:upload_id/:chunk_number
func UploadChunkHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Check if chunked uploads are enabled
		if !cfg.ChunkedUploadEnabled {
			sendError(w, "Chunked uploads are disabled", "FEATURE_DISABLED", http.StatusServiceUnavailable)
			return
		}

		// Extract upload_id and chunk_number from URL path
		// Path format: /api/upload/chunk/{upload_id}/{chunk_number}
		pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/upload/chunk/"), "/")
		if len(pathParts) != 2 {
			sendError(w, "Invalid URL path", "INVALID_PATH", http.StatusBadRequest)
			return
		}

		uploadID := pathParts[0]
		chunkNumberStr := pathParts[1]

		// Validate upload_id (UUID format)
		if _, err := uuid.Parse(uploadID); err != nil {
			sendError(w, "Invalid upload_id format", "INVALID_UPLOAD_ID", http.StatusBadRequest)
			return
		}

		// Parse chunk_number
		chunkNumber, err := strconv.Atoi(chunkNumberStr)
		if err != nil || chunkNumber < 0 {
			sendError(w, "Invalid chunk_number", "INVALID_CHUNK_NUMBER", http.StatusBadRequest)
			return
		}

		// Get partial upload from database
		partialUpload, err := database.GetPartialUpload(db, uploadID)
		if err != nil {
			slog.Error("failed to get partial upload", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if partialUpload == nil {
			sendError(w, "Upload session not found", "UPLOAD_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if upload is already completed
		if partialUpload.Completed {
			sendError(w, "Upload already completed", "UPLOAD_COMPLETED", http.StatusConflict)
			return
		}

		// Check if upload has expired (based on last activity)
		expiryTime := partialUpload.LastActivity.Add(time.Duration(cfg.PartialUploadExpiryHours) * time.Hour)
		if time.Now().After(expiryTime) {
			sendError(w, "Upload session expired", "UPLOAD_EXPIRED", http.StatusGone)
			return
		}

		// Validate chunk_number is within range
		if chunkNumber >= partialUpload.TotalChunks {
			sendSmartError(w,
				fmt.Sprintf("Chunk number %d exceeds total chunks %d", chunkNumber, partialUpload.TotalChunks),
				"CHUNK_NUMBER_OUT_OF_RANGE",
				http.StatusBadRequest,
			)
			return
		}

		// Check if chunk already exists (idempotency)
		exists, existingSize, err := utils.ChunkExists(cfg.UploadDir, uploadID, chunkNumber)
		if err != nil {
			slog.Error("failed to check chunk existence", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Parse multipart form with the requested chunk size (not config default)
		maxChunkSize := partialUpload.ChunkSize + 1024 // requested chunk size + 1KB overhead
		r.Body = http.MaxBytesReader(w, r.Body, maxChunkSize)
		if err := r.ParseMultipartForm(maxChunkSize); err != nil {
			sendError(w, "Chunk too large or invalid form data", "CHUNK_TOO_LARGE", http.StatusRequestEntityTooLarge)
			return
		}

		// Get chunk file from form
		chunkFile, chunkHeader, err := r.FormFile("chunk")
		if err != nil {
			sendError(w, "No chunk file provided", "NO_CHUNK", http.StatusBadRequest)
			return
		}
		defer chunkFile.Close()

		// Read chunk data
		chunkData, err := io.ReadAll(chunkFile)
		if err != nil {
			slog.Error("failed to read chunk data", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Calculate SHA256 checksum of chunk
		hash := sha256.Sum256(chunkData)
		checksum := hex.EncodeToString(hash[:])

		chunkSize := int64(len(chunkData))

		// Validate chunk size
		expectedChunkSize := partialUpload.ChunkSize
		isLastChunk := chunkNumber == partialUpload.TotalChunks-1

		if !isLastChunk {
			// Not the last chunk - must match expected size exactly
			if chunkSize != expectedChunkSize {
				sendSmartError(w,
					fmt.Sprintf("Chunk size mismatch: expected %d, got %d", expectedChunkSize, chunkSize),
					"CHUNK_SIZE_MISMATCH",
					http.StatusBadRequest,
				)
				return
			}
		} else {
			// Last chunk - calculate expected size (P1 security fix: prevent integer underflow)
			lastChunkSize := partialUpload.TotalSize - (int64(partialUpload.TotalChunks-1) * expectedChunkSize)
			// Validate that lastChunkSize is positive (detect database corruption/manipulation)
			if lastChunkSize <= 0 {
				slog.Error("invalid last chunk size calculation (possible database corruption)",
					"upload_id", uploadID,
					"total_size", partialUpload.TotalSize,
					"total_chunks", partialUpload.TotalChunks,
					"expected_chunk_size", expectedChunkSize,
					"calculated_last_chunk_size", lastChunkSize,
				)
				sendSmartError(w,
					"Invalid upload metadata - possible corruption",
					"INVALID_METADATA",
					http.StatusInternalServerError,
				)
				return
			}
			if chunkSize != lastChunkSize {
				sendSmartError(w,
					fmt.Sprintf("Last chunk size mismatch: expected %d, got %d", lastChunkSize, chunkSize),
					"CHUNK_SIZE_MISMATCH",
					http.StatusBadRequest,
				)
				return
			}
		}

		// If chunk exists, verify it matches (idempotency check)
		if exists {
			if existingSize == chunkSize {
				// Read existing chunk to calculate checksum
				existingData, err := os.ReadFile(utils.GetChunkPath(cfg.UploadDir, uploadID, chunkNumber))
				var existingChecksum string
				if err == nil {
					hash := sha256.Sum256(existingData)
					existingChecksum = hex.EncodeToString(hash[:])
				} else {
					// If we can't read the chunk for checksum, log warning but continue
					slog.Warn("failed to read existing chunk for checksum verification",
						"error", err,
						"upload_id", uploadID,
						"chunk_number", chunkNumber,
					)
					existingChecksum = "" // Empty checksum indicates verification skipped
				}

				// Chunk already exists with same size - treat as success (idempotent)
				slog.Debug("chunk already exists (idempotent)",
					"upload_id", uploadID,
					"chunk_number", chunkNumber,
					"size", chunkSize,
					"checksum", existingChecksum,
				)

				// Update activity time
				if err := database.UpdatePartialUploadActivity(db, uploadID); err != nil {
					slog.Error("failed to update partial upload activity", "error", err)
				}

				// Count actual chunks from disk instead of relying on DB counter
				chunksReceived, err := utils.GetChunkCount(cfg.UploadDir, uploadID)
				if err != nil {
					slog.Warn("failed to get chunk count", "error", err, "upload_id", uploadID)
					chunksReceived = 0
				}

				// Return success response
				response := models.UploadChunkResponse{
					UploadID:       uploadID,
					ChunkNumber:    chunkNumber,
					ChunksReceived: chunksReceived,
					TotalChunks:    partialUpload.TotalChunks,
					Complete:       chunksReceived == partialUpload.TotalChunks,
					Checksum:       existingChecksum,
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				return
			} else {
				// Chunk exists but with different size - corruption
				sendSmartError(w,
					fmt.Sprintf("Chunk %d already exists with different size (expected %d, got %d). Possible corruption.",
						chunkNumber, existingSize, chunkSize),
					"CHUNK_CORRUPTION",
					http.StatusConflict,
				)
				return
			}
		}

		// Check disk space before saving chunk
		// Skip percentage check if quota is configured (quota takes precedence)
		quotaConfigured := cfg.GetQuotaLimitGB() > 0
		hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, chunkSize, quotaConfigured)
		if err != nil {
			slog.Error("failed to check disk space", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !hasSpace {
			slog.Warn("insufficient disk space for chunk",
				"upload_id", uploadID,
				"chunk_number", chunkNumber,
				"chunk_size", chunkSize,
				"reason", errMsg,
			)
			sendSmartError(w, errMsg, "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
			return
		}

		// Save chunk to disk
		if err := utils.SaveChunk(cfg.UploadDir, uploadID, chunkNumber, chunkData); err != nil {
			slog.Error("failed to save chunk", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Update last_activity to prevent cleanup worker from removing active uploads
		if err := database.UpdatePartialUploadActivity(db, uploadID); err != nil {
			slog.Error("failed to update partial upload activity", "error", err)
			// Non-fatal error - continue processing
		}

		// NOTE: We no longer increment chunks_received in the database on every chunk upload.
		// This caused severe database lock contention (31-35% SQLITE_BUSY errors with concurrency=3).
		// Instead, chunk count is calculated on-demand from disk when status is requested.
		// This eliminates all database writes during upload, allowing higher concurrency.

		// Count actual chunks from disk instead of relying on DB counter
		chunksReceived, err := utils.GetChunkCount(cfg.UploadDir, uploadID)
		if err != nil {
			slog.Warn("failed to get chunk count", "error", err, "upload_id", uploadID)
			// Use 0 as fallback if we can't count chunks
			chunksReceived = 0
		}

		response := models.UploadChunkResponse{
			UploadID:       uploadID,
			ChunkNumber:    chunkNumber,
			ChunksReceived: chunksReceived,
			TotalChunks:    partialUpload.TotalChunks,
			Complete:       chunksReceived >= partialUpload.TotalChunks,
			Checksum:       checksum,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

		// Record metrics
		metrics.ChunkedUploadChunksTotal.Inc()

		slog.Debug("chunk uploaded",
			"upload_id", uploadID,
			"chunk_number", chunkNumber,
			"chunk_size", chunkSize,
			"chunks_received", chunksReceived,
			"total_chunks", partialUpload.TotalChunks,
			"filename", chunkHeader.Filename,
		)
	}
}

// UploadCompleteHandler handles POST /api/upload/complete/:upload_id
func UploadCompleteHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Check if chunked uploads are enabled
		if !cfg.ChunkedUploadEnabled {
			sendError(w, "Chunked uploads are disabled", "FEATURE_DISABLED", http.StatusServiceUnavailable)
			return
		}

		// Extract upload_id from URL path
		uploadID := strings.TrimPrefix(r.URL.Path, "/api/upload/complete/")

		// Validate upload_id (UUID format)
		if _, err := uuid.Parse(uploadID); err != nil {
			sendError(w, "Invalid upload_id format", "INVALID_UPLOAD_ID", http.StatusBadRequest)
			return
		}

		// Get partial upload from database
		partialUpload, err := database.GetPartialUpload(db, uploadID)
		if err != nil {
			slog.Error("failed to get partial upload", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if partialUpload == nil {
			sendError(w, "Upload session not found", "UPLOAD_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check if already completed or processing
		if partialUpload.Status == "completed" {
			// Already completed - return existing claim code with full file info
			if partialUpload.ClaimCode != nil {
				downloadURL := buildDownloadURL(r, cfg, *partialUpload.ClaimCode)

				// Calculate expiration time
				var expiresAt time.Time
				if partialUpload.ExpiresInHours == 0 {
					// Never expire - set to 100 years in the future
					expiresAt = partialUpload.CreatedAt.Add(time.Duration(100*365*24) * time.Hour)
				} else {
					expiresAt = partialUpload.CreatedAt.Add(time.Duration(partialUpload.ExpiresInHours) * time.Hour)
				}

				response := models.UploadCompleteResponse{
					ClaimCode:          *partialUpload.ClaimCode,
					DownloadURL:        downloadURL,
					OriginalFilename:   partialUpload.Filename,
					FileSize:           partialUpload.TotalSize,
					ExpiresAt:          expiresAt,
					MaxDownloads:       partialUpload.MaxDownloads,
					CompletedDownloads: 0, // New uploads have 0 downloads
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				return
			}
		}

		// If already processing, return status (idempotent completion request)
		if partialUpload.Status == "processing" {
			response := map[string]interface{}{
				"status":    "processing",
				"upload_id": uploadID,
				"message":   "File is being assembled. Please poll /api/upload/status/" + uploadID + " for completion.",
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted) // 202 Accepted
			json.NewEncoder(w).Encode(response)
			return
		}

		// Check if upload has expired
		expiryTime := partialUpload.LastActivity.Add(time.Duration(cfg.PartialUploadExpiryHours) * time.Hour)
		if time.Now().After(expiryTime) {
			sendError(w, "Upload session expired", "UPLOAD_EXPIRED", http.StatusGone)
			return
		}

		// Check for missing chunks
		missingChunks, err := utils.GetMissingChunks(cfg.UploadDir, uploadID, partialUpload.TotalChunks)
		if err != nil {
			slog.Error("failed to check for missing chunks", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if len(missingChunks) > 0 {
			slog.Warn("cannot complete upload: chunks missing",
				"upload_id", uploadID,
				"missing_count", len(missingChunks),
				"first_missing", missingChunks[0],
			)

			// Return error with list of missing chunks
			errorResp := models.UploadCompleteErrorResponse{
				Error:         fmt.Sprintf("Missing %d chunks", len(missingChunks)),
				MissingChunks: missingChunks,
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(errorResp)
			return
		}

		// Verify chunk integrity (optional but recommended)
		if err := utils.VerifyChunkIntegrity(cfg.UploadDir, uploadID, partialUpload.TotalChunks,
			partialUpload.ChunkSize, partialUpload.TotalSize); err != nil {
			slog.Error("chunk integrity verification failed", "error", err, "upload_id", uploadID)
			sendError(w, fmt.Sprintf("Chunk integrity check failed: %v", err), "INTEGRITY_ERROR", http.StatusBadRequest)
			return
		}

		// Check disk space for final file
		// Skip percentage check if quota is configured (quota takes precedence)
		quotaConfigured := cfg.GetQuotaLimitGB() > 0
		hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, partialUpload.TotalSize, quotaConfigured)
		if err != nil {
			slog.Error("failed to check disk space", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !hasSpace {
			slog.Warn("insufficient disk space for final file",
				"upload_id", uploadID,
				"file_size", partialUpload.TotalSize,
				"reason", errMsg,
			)
			sendSmartError(w, errMsg, "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
			return
		}

		// Try to atomically lock the upload for processing (prevents race conditions)
		locked, err := database.TryLockUploadForProcessing(db, uploadID)
		if err != nil {
			slog.Error("failed to lock upload for processing", "error", err, "upload_id", uploadID)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if !locked {
			// Another request is already processing this upload
			slog.Debug("upload already locked for processing", "upload_id", uploadID)
			response := map[string]interface{}{
				"status":    "processing",
				"upload_id": uploadID,
				"message":   "File is being assembled. Please poll /api/upload/status/" + uploadID + " for completion.",
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted) // 202 Accepted
			json.NewEncoder(w).Encode(response)
			return
		}

		// Get client IP for logging
		clientIP := getClientIP(r)

		// Spawn goroutine to assemble file asynchronously with concurrency limit
		// Copy partialUpload to avoid data races (partialUpload is a pointer)
		partialUploadCopy := *partialUpload
		go func() {
			// Acquire semaphore slot (blocks if 10 assemblies already running)
			assemblySemaphore <- struct{}{}
			defer func() { <-assemblySemaphore }() // Release slot when done

			AssembleUploadAsync(db, cfg, &partialUploadCopy, clientIP)
		}()

		// Record metrics
		metrics.ChunkedUploadsCompletedTotal.Inc()
		metrics.UploadSizeBytes.Observe(float64(partialUpload.TotalSize))

		// Return immediately with status "processing"
		slog.Info("chunked upload accepted for async assembly",
			"upload_id", uploadID,
			"filename", partialUpload.Filename,
			"size", partialUpload.TotalSize,
			"total_chunks", partialUpload.TotalChunks,
			"client_ip", clientIP,
		)

		response := map[string]interface{}{
			"status":    "processing",
			"upload_id": uploadID,
			"message":   "File is being assembled. Please poll /api/upload/status/" + uploadID + " for completion.",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202 Accepted
		json.NewEncoder(w).Encode(response)
	}
}

// UploadStatusHandler handles GET /api/upload/status/:upload_id
func UploadStatusHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept GET requests
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Check if chunked uploads are enabled
		if !cfg.ChunkedUploadEnabled {
			sendError(w, "Chunked uploads are disabled", "FEATURE_DISABLED", http.StatusServiceUnavailable)
			return
		}

		// Extract upload_id from URL path
		uploadID := strings.TrimPrefix(r.URL.Path, "/api/upload/status/")

		// Validate upload_id (UUID format)
		if _, err := uuid.Parse(uploadID); err != nil {
			sendError(w, "Invalid upload_id format", "INVALID_UPLOAD_ID", http.StatusBadRequest)
			return
		}

		// Get partial upload from database
		partialUpload, err := database.GetPartialUpload(db, uploadID)
		if err != nil {
			slog.Error("failed to get partial upload", "error", err)
			sendSmartError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if partialUpload == nil {
			sendError(w, "Upload session not found", "UPLOAD_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Calculate expiration time
		expiresAt := partialUpload.LastActivity.Add(time.Duration(cfg.PartialUploadExpiryHours) * time.Hour)

		// Get missing chunks (if not completed)
		var missingChunks []int
		if !partialUpload.Completed {
			missing, err := utils.GetMissingChunks(cfg.UploadDir, uploadID, partialUpload.TotalChunks)
			if err != nil {
				slog.Error("failed to get missing chunks", "error", err)
				// Don't fail the request - just skip missing chunks in response
			} else {
				missingChunks = missing
			}
		}

		// Count actual chunks from disk
		chunksReceived, _ := utils.GetChunkCount(cfg.UploadDir, uploadID)

		// Build download URL if completed
		var downloadURL *string
		if partialUpload.Status == "completed" && partialUpload.ClaimCode != nil {
			url := buildDownloadURL(r, cfg, *partialUpload.ClaimCode)
			downloadURL = &url
		}

		// Build response
		response := models.UploadStatusResponse{
			UploadID:           uploadID,
			Filename:           partialUpload.Filename,
			ChunksReceived:     chunksReceived,
			TotalChunks:        partialUpload.TotalChunks,
			MissingChunks:      missingChunks,
			Complete:           partialUpload.Completed,
			ExpiresAt:          expiresAt,
			ClaimCode:          partialUpload.ClaimCode,
			Status:             partialUpload.Status,
			ErrorMessage:       partialUpload.ErrorMessage,
			DownloadURL:        downloadURL,
			FileSize:           partialUpload.TotalSize,
			MaxDownloads:       partialUpload.MaxDownloads,
			CompletedDownloads: 0, // TODO: Get actual download count from files table once completed
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
