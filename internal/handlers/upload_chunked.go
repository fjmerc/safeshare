package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/google/uuid"
)

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
			sendError(w,
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
			sendError(w,
				fmt.Sprintf("File size exceeds maximum of %d bytes", cfg.GetMaxFileSize()),
				"FILE_TOO_LARGE",
				http.StatusRequestEntityTooLarge,
			)
			return
		}

		// Calculate total chunks using server-configured chunk size
		// (client's chunk_size in request is ignored)
		totalChunks := int(req.TotalSize / cfg.ChunkSize)
		if req.TotalSize%cfg.ChunkSize != 0 {
			totalChunks++
		}

		// Validate total chunks (prevent DoS with too many small chunks)
		if totalChunks > 10000 {
			sendError(w,
				"File requires too many chunks (maximum 10,000). Try increasing chunk size.",
				"TOO_MANY_CHUNKS",
				http.StatusBadRequest,
			)
			return
		}

		// Validate expiration hours
		if req.ExpiresInHours <= 0 {
			req.ExpiresInHours = cfg.GetDefaultExpirationHours()
		}

		if req.ExpiresInHours > cfg.GetMaxExpirationHours() {
			sendError(w,
				fmt.Sprintf("Expiration time exceeds maximum allowed (%d hours)", cfg.GetMaxExpirationHours()),
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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !hasSpace {
			slog.Warn("insufficient disk space for chunked upload init",
				"file_size", req.TotalSize,
				"client_ip", getClientIP(r),
				"reason", errMsg,
			)
			sendError(w, errMsg, "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
			return
		}

		// Check quota if configured (0 = unlimited)
		if quotaConfigured {
			// Get current usage (includes both completed files and partial uploads)
			currentUsage, err := database.GetTotalUsage(db)
			if err != nil {
				slog.Error("failed to get storage usage", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			quotaBytes := cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024

			if currentUsage+req.TotalSize > quotaBytes {
				quotaUsedGB := float64(currentUsage) / (1024 * 1024 * 1024)
				slog.Warn("quota exceeded for chunked upload init",
					"file_size", req.TotalSize,
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

		// Hash password if provided
		var passwordHash string
		if req.Password != "" {
			hash, err := utils.HashPassword(req.Password)
			if err != nil {
				slog.Error("failed to hash password", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			passwordHash = hash
		}

		// Get user ID if authenticated
		var userID *int64
		if user, ok := r.Context().Value("user").(*models.User); ok && user != nil {
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
			ChunkSize:      cfg.ChunkSize,
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

		if err := database.CreatePartialUpload(db, partialUpload); err != nil {
			slog.Error("failed to create partial upload", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Calculate expiration time
		expiresAt := time.Now().Add(time.Duration(cfg.PartialUploadExpiryHours) * time.Hour)

		// Send response
		response := models.UploadInitResponse{
			UploadID:    uploadID,
			ChunkSize:   cfg.ChunkSize,
			TotalChunks: totalChunks,
			ExpiresAt:   expiresAt,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)

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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
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
			sendError(w,
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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		chunkSize := int64(len(chunkData))

		// Validate chunk size
		expectedChunkSize := partialUpload.ChunkSize
		isLastChunk := chunkNumber == partialUpload.TotalChunks-1

		if !isLastChunk {
			// Not the last chunk - must match expected size exactly
			if chunkSize != expectedChunkSize {
				sendError(w,
					fmt.Sprintf("Chunk size mismatch: expected %d, got %d", expectedChunkSize, chunkSize),
					"CHUNK_SIZE_MISMATCH",
					http.StatusBadRequest,
				)
				return
			}
		} else {
			// Last chunk - calculate expected size
			lastChunkSize := partialUpload.TotalSize - (int64(partialUpload.TotalChunks-1) * expectedChunkSize)
			if chunkSize != lastChunkSize {
				sendError(w,
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
				// Chunk already exists with same size - treat as success (idempotent)
				slog.Debug("chunk already exists (idempotent)",
					"upload_id", uploadID,
					"chunk_number", chunkNumber,
					"size", chunkSize,
				)

				// Update activity time
				if err := database.UpdatePartialUploadActivity(db, uploadID); err != nil {
					slog.Error("failed to update partial upload activity", "error", err)
				}

				// Count actual chunks from disk instead of relying on DB counter
				chunksReceived, _ := utils.GetChunkCount(cfg.UploadDir, uploadID)

				// Return success response
				response := models.UploadChunkResponse{
					UploadID:       uploadID,
					ChunkNumber:    chunkNumber,
					ChunksReceived: chunksReceived,
					TotalChunks:    partialUpload.TotalChunks,
					Complete:       chunksReceived == partialUpload.TotalChunks,
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				return
			} else {
				// Chunk exists but with different size - corruption
				sendError(w,
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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !hasSpace {
			slog.Warn("insufficient disk space for chunk",
				"upload_id", uploadID,
				"chunk_number", chunkNumber,
				"chunk_size", chunkSize,
				"reason", errMsg,
			)
			sendError(w, errMsg, "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
			return
		}

		// Save chunk to disk
		if err := utils.SaveChunk(cfg.UploadDir, uploadID, chunkNumber, chunkData); err != nil {
			slog.Error("failed to save chunk", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// NOTE: We no longer increment chunks_received in the database on every chunk upload.
		// This caused severe database lock contention (31-35% SQLITE_BUSY errors with concurrency=3).
		// Instead, chunk count is calculated on-demand from disk when status is requested.
		// This eliminates all database writes during upload, allowing higher concurrency.

		// Count actual chunks from disk instead of relying on DB counter
		chunksReceived, _ := utils.GetChunkCount(cfg.UploadDir, uploadID)

		response := models.UploadChunkResponse{
			UploadID:       uploadID,
			ChunkNumber:    chunkNumber,
			ChunksReceived: chunksReceived,
			TotalChunks:    partialUpload.TotalChunks,
			Complete:       chunksReceived >= partialUpload.TotalChunks,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
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
				expiresAt := partialUpload.CreatedAt.Add(time.Duration(partialUpload.ExpiresInHours) * time.Hour)

				response := models.UploadCompleteResponse{
					ClaimCode:        *partialUpload.ClaimCode,
					DownloadURL:      downloadURL,
					OriginalFilename: partialUpload.Filename,
					FileSize:         partialUpload.TotalSize,
					ExpiresAt:        expiresAt,
					MaxDownloads:     partialUpload.MaxDownloads,
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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if !hasSpace {
			slog.Warn("insufficient disk space for final file",
				"upload_id", uploadID,
				"file_size", partialUpload.TotalSize,
				"reason", errMsg,
			)
			sendError(w, errMsg, "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
			return
		}

		// Try to atomically lock the upload for processing (prevents race conditions)
		locked, err := database.TryLockUploadForProcessing(db, uploadID)
		if err != nil {
			slog.Error("failed to lock upload for processing", "error", err, "upload_id", uploadID)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
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

		// Spawn goroutine to assemble file asynchronously
		// Copy partialUpload to avoid data races (partialUpload is a pointer)
		partialUploadCopy := *partialUpload
		go AssembleUploadAsync(db, cfg, &partialUploadCopy, clientIP)

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
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
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
			UploadID:       uploadID,
			Filename:       partialUpload.Filename,
			ChunksReceived: chunksReceived,
			TotalChunks:    partialUpload.TotalChunks,
			MissingChunks:  missingChunks,
			Complete:       partialUpload.Completed,
			ExpiresAt:      expiresAt,
			ClaimCode:      partialUpload.ClaimCode,
			Status:         partialUpload.Status,
			ErrorMessage:   partialUpload.ErrorMessage,
			DownloadURL:    downloadURL,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
