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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
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

		// Validate chunk_size (must be between 1MB and 10MB)
		if req.ChunkSize < 1048576 || req.ChunkSize > 10485760 {
			sendError(w, "Chunk size must be between 1MB and 10MB", "INVALID_CHUNK_SIZE", http.StatusBadRequest)
			return
		}

		// Calculate total chunks
		totalChunks := int(req.TotalSize / req.ChunkSize)
		if req.TotalSize%req.ChunkSize != 0 {
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

		// Validate max downloads
		if req.MaxDownloads <= 0 {
			req.MaxDownloads = 1 // Default to 1 download
		}

		// Check disk space before accepting upload
		hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, req.TotalSize)
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
		if cfg.GetQuotaLimitGB() > 0 {
			// Get current usage from both completed files and partial uploads
			completedUsage, err := database.GetTotalUsage(db)
			if err != nil {
				slog.Error("failed to get completed storage usage", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			partialUsage, err := database.GetTotalPartialUploadUsage(db)
			if err != nil {
				slog.Error("failed to get partial upload usage", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			currentUsage := completedUsage + partialUsage
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
			ChunkSize:      req.ChunkSize,
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
			ChunkSize:   req.ChunkSize,
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
			"chunk_size", req.ChunkSize,
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

		// Parse multipart form
		r.Body = http.MaxBytesReader(w, r.Body, cfg.ChunkSize+1024) // chunk size + 1KB overhead
		if err := r.ParseMultipartForm(cfg.ChunkSize + 1024); err != nil {
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

				// Return success response
				response := models.UploadChunkResponse{
					UploadID:       uploadID,
					ChunkNumber:    chunkNumber,
					ChunksReceived: partialUpload.ChunksReceived,
					TotalChunks:    partialUpload.TotalChunks,
					Complete:       partialUpload.ChunksReceived == partialUpload.TotalChunks,
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
		hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, chunkSize)
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

		// Increment chunks_received in database
		if err := database.IncrementChunksReceived(db, uploadID, chunkSize); err != nil {
			slog.Error("failed to increment chunks received", "error", err)
			// Don't fail the request - chunk is already saved
		}

		// Refresh partial upload data to get updated counts
		partialUpload, err = database.GetPartialUpload(db, uploadID)
		if err != nil {
			slog.Error("failed to refresh partial upload", "error", err)
			// Don't fail - use old data
		}

		// Send response
		response := models.UploadChunkResponse{
			UploadID:       uploadID,
			ChunkNumber:    chunkNumber,
			ChunksReceived: partialUpload.ChunksReceived,
			TotalChunks:    partialUpload.TotalChunks,
			Complete:       partialUpload.ChunksReceived >= partialUpload.TotalChunks,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

		slog.Debug("chunk uploaded",
			"upload_id", uploadID,
			"chunk_number", chunkNumber,
			"chunk_size", chunkSize,
			"chunks_received", partialUpload.ChunksReceived,
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

		// Check if already completed
		if partialUpload.Completed {
			// Already completed - return existing claim code
			if partialUpload.ClaimCode != nil {
				downloadURL := buildDownloadURL(r, cfg, *partialUpload.ClaimCode)
				response := models.UploadCompleteResponse{
					ClaimCode:   *partialUpload.ClaimCode,
					DownloadURL: downloadURL,
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(response)
				return
			}
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
		hasSpace, errMsg, err := utils.CheckDiskSpace(cfg.UploadDir, partialUpload.TotalSize)
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

		// Generate unique claim code
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
		storedFilename := uuid.New().String() + filepath.Ext(partialUpload.Filename)
		finalPath := filepath.Join(cfg.UploadDir, storedFilename)

		// Assemble chunks into final file
		slog.Info("assembling chunks into final file",
			"upload_id", uploadID,
			"total_chunks", partialUpload.TotalChunks,
			"filename", partialUpload.Filename,
		)

		totalBytesWritten, err := utils.AssembleChunks(cfg.UploadDir, uploadID, partialUpload.TotalChunks, finalPath)
		if err != nil {
			slog.Error("failed to assemble chunks", "error", err, "upload_id", uploadID)
			// Clean up partial final file if it exists
			os.Remove(finalPath)
			sendError(w, "Failed to assemble file", "ASSEMBLY_ERROR", http.StatusInternalServerError)
			return
		}

		// Verify assembled file size matches expected
		if totalBytesWritten != partialUpload.TotalSize {
			slog.Error("assembled file size mismatch",
				"upload_id", uploadID,
				"expected", partialUpload.TotalSize,
				"actual", totalBytesWritten,
			)
			os.Remove(finalPath)
			sendError(w, "Assembled file size mismatch", "SIZE_MISMATCH", http.StatusInternalServerError)
			return
		}

		// Encrypt if encryption is enabled
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			slog.Debug("encrypting assembled file", "upload_id", uploadID)

			// Read file
			fileData, err := os.ReadFile(finalPath)
			if err != nil {
				slog.Error("failed to read file for encryption", "error", err)
				os.Remove(finalPath)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			// Encrypt
			encrypted, err := utils.EncryptFile(fileData, cfg.EncryptionKey)
			if err != nil {
				slog.Error("failed to encrypt file", "error", err)
				os.Remove(finalPath)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			// Write encrypted data back
			if err := os.WriteFile(finalPath, encrypted, 0644); err != nil {
				slog.Error("failed to write encrypted file", "error", err)
				os.Remove(finalPath)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			slog.Debug("file encrypted", "upload_id", uploadID, "original_size", len(fileData), "encrypted_size", len(encrypted))
		}

		// Detect MIME type from assembled file (only read first 512 bytes for magic number detection)
		mimeType := "application/octet-stream"
		if !utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			file, err := os.Open(finalPath)
			if err != nil {
				slog.Error("failed to open file for MIME detection", "error", err)
				os.Remove(finalPath)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			// Only read first 512 bytes for MIME detection (sufficient for magic number detection)
			buffer := make([]byte, 512)
			n, err := file.Read(buffer)
			file.Close()

			if err != nil && err != io.EOF {
				slog.Error("failed to read file for MIME detection", "error", err)
				os.Remove(finalPath)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			detected := utils.DetectMimeType(buffer[:n])
			if detected != "" {
				mimeType = detected
			}
		}

		// Get client IP
		clientIP := getClientIP(r)

		// Calculate expiration time
		expiresAt := time.Now().Add(time.Duration(partialUpload.ExpiresInHours) * time.Hour)

		// Create file record in database
		var maxDownloads *int
		if partialUpload.MaxDownloads > 0 {
			maxDownloads = &partialUpload.MaxDownloads
		}

		fileRecord := &models.File{
			ClaimCode:        claimCode,
			OriginalFilename: partialUpload.Filename,
			StoredFilename:   storedFilename,
			FileSize:         partialUpload.TotalSize,
			MimeType:         mimeType,
			ExpiresAt:        expiresAt,
			MaxDownloads:     maxDownloads,
			UploaderIP:       clientIP,
			PasswordHash:     partialUpload.PasswordHash,
			UserID:           partialUpload.UserID,
		}

		if err := database.CreateFile(db, fileRecord); err != nil {
			os.Remove(finalPath) // Clean up on error
			slog.Error("failed to create file record", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Mark partial upload as completed
		if err := database.MarkPartialUploadCompleted(db, uploadID, claimCode); err != nil {
			slog.Error("failed to mark partial upload as completed", "error", err)
			// Don't fail the request - file is already created
		}

		// Delete chunks (cleanup)
		if err := utils.DeleteChunks(cfg.UploadDir, uploadID); err != nil {
			slog.Error("failed to delete chunks", "error", err, "upload_id", uploadID)
			// Don't fail the request - chunks will be cleaned up later
		}

		// Delete partial upload record
		if err := database.DeletePartialUpload(db, uploadID); err != nil {
			slog.Error("failed to delete partial upload record", "error", err)
			// Don't fail the request - will be cleaned up later
		}

		// Build download URL
		downloadURL := buildDownloadURL(r, cfg, claimCode)

		// Send response
		response := models.UploadCompleteResponse{
			ClaimCode:   claimCode,
			DownloadURL: downloadURL,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

		slog.Info("chunked upload completed",
			"upload_id", uploadID,
			"claim_code", redactClaimCode(claimCode),
			"filename", partialUpload.Filename,
			"size", partialUpload.TotalSize,
			"total_chunks", partialUpload.TotalChunks,
			"expires_at", expiresAt,
			"password_protected", partialUpload.PasswordHash != "",
			"client_ip", clientIP,
		)
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

		// Build response
		response := models.UploadStatusResponse{
			UploadID:       uploadID,
			Filename:       partialUpload.Filename,
			ChunksReceived: partialUpload.ChunksReceived,
			TotalChunks:    partialUpload.TotalChunks,
			MissingChunks:  missingChunks,
			Complete:       partialUpload.Completed,
			ExpiresAt:      expiresAt,
			ClaimCode:      partialUpload.ClaimCode,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}
