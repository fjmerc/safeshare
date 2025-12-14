package handlers

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
	"github.com/google/uuid"
)

// AssembleUploadAsync performs the file assembly in a background goroutine
// This function is called after all chunks have been uploaded and validated
func AssembleUploadAsync(repos *repository.Repositories, cfg *config.Config, partialUpload *models.PartialUpload, clientIP string) {
	// This function runs in a goroutine, so we must handle all errors internally
	// and update the database status accordingly

	uploadID := partialUpload.UploadID
	ctx := context.Background() // Background context for async worker

	// Add panic recovery to prevent goroutine death and orphaned files
	defer func() {
		if r := recover(); r != nil {
			slog.Error("assembly worker panic recovered",
				"upload_id", uploadID,
				"panic", r,
			)
			if err := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Assembly panicked: %v", r)); err != nil {
				slog.Error("failed to mark assembly as failed after panic", "error", err, "upload_id", uploadID)
			}
		}
	}()

	slog.Info("starting async assembly",
		"upload_id", uploadID,
		"filename", partialUpload.Filename,
		"total_chunks", partialUpload.TotalChunks,
		"total_size", partialUpload.TotalSize,
	)

	// Generate unique claim code
	var claimCode string
	var err error
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		claimCode, err = utils.GenerateClaimCode()
		if err != nil {
			slog.Error("failed to generate claim code", "error", err, "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to generate claim code: %v", err)); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		// Check if code already exists
		existing, err := repos.Files.GetByClaimCode(ctx, claimCode)
		if err != nil {
			slog.Error("failed to check claim code", "error", err, "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to check claim code: %v", err)); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		if existing == nil {
			break // Code is unique
		}

		if i == maxRetries-1 {
			slog.Error("failed to generate unique claim code after retries", "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, "Failed to generate unique claim code"); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}
	}

	// Generate unique filename for storage
	storedFilename := uuid.New().String() + filepath.Ext(partialUpload.Filename)
	finalPath := filepath.Join(cfg.UploadDir, storedFilename)

	// Assemble chunks into final file (also computes SHA256 hash)
	slog.Info("assembling chunks into final file",
		"upload_id", uploadID,
		"total_chunks", partialUpload.TotalChunks,
		"filename", partialUpload.Filename,
	)

	totalBytesWritten, sha256Hash, err := utils.AssembleChunks(cfg.UploadDir, uploadID, partialUpload.TotalChunks, finalPath)
	if err != nil {
		slog.Error("failed to assemble chunks", "error", err, "upload_id", uploadID)
		os.Remove(finalPath) // Clean up partial final file if it exists
		if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to assemble file: %v", err)); setErr != nil {
			slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
		}
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
		if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Assembled file size mismatch: expected %d, got %d", partialUpload.TotalSize, totalBytesWritten)); setErr != nil {
			slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
		}
		return
	}

	slog.Info("chunk assembly complete",
		"upload_id", uploadID,
		"total_bytes", totalBytesWritten,
	)

	// Encrypt if encryption is enabled
	if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
		slog.Debug("encrypting assembled file using streaming encryption", "upload_id", uploadID)

		// Use streaming encryption to avoid loading entire file into memory
		// Encrypt to temporary file, then replace original
		tempEncryptedPath := finalPath + ".encrypted.tmp"

		if err := utils.EncryptFileStreaming(finalPath, tempEncryptedPath, cfg.EncryptionKey); err != nil {
			slog.Error("failed to encrypt file", "error", err, "upload_id", uploadID)
			os.Remove(finalPath)
			os.Remove(tempEncryptedPath)
			repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to encrypt file: %v", err))
			return
		}

		// Get file sizes for logging
		originalInfo, _ := os.Stat(finalPath)
		encryptedInfo, _ := os.Stat(tempEncryptedPath)

		// Replace original with encrypted version
		if err := os.Remove(finalPath); err != nil {
			slog.Error("failed to remove original file", "error", err, "upload_id", uploadID)
			os.Remove(tempEncryptedPath)
			repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to remove original file: %v", err))
			return
		}
		if err := os.Rename(tempEncryptedPath, finalPath); err != nil {
			slog.Error("failed to rename encrypted file", "error", err, "upload_id", uploadID)
			os.Remove(tempEncryptedPath)
			repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to rename encrypted file: %v", err))
			return
		}

		slog.Debug("file encrypted with streaming encryption",
			"upload_id", uploadID,
			"original_size", originalInfo.Size(),
			"encrypted_size", encryptedInfo.Size())
	}

	// Detect MIME type from assembled file (only read first 512 bytes for magic number detection)
	mimeType := "application/octet-stream"
	if !utils.IsEncryptionEnabled(cfg.EncryptionKey) {
		file, err := os.Open(finalPath)
		if err != nil {
			slog.Error("failed to open file for MIME detection", "error", err, "upload_id", uploadID)
			os.Remove(finalPath)
			repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to open file for MIME detection: %v", err))
			return
		}

		// Only read first 512 bytes for MIME detection (sufficient for magic number detection)
		buffer := make([]byte, 512)
		n, err := file.Read(buffer)
		file.Close()

		if err != nil && err != io.EOF {
			slog.Error("failed to read file for MIME detection", "error", err, "upload_id", uploadID)
			os.Remove(finalPath)
			repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to read file for MIME detection: %v", err))
			return
		}

		detected := utils.DetectMimeType(buffer[:n])
		if detected != "" {
			mimeType = detected
		}
	}

	// Calculate expiration time
	var expiresAt time.Time
	if partialUpload.ExpiresInHours == 0 {
		// Never expire - set to 100 years in the future
		expiresAt = partialUpload.CreatedAt.Add(time.Duration(100*365*24) * time.Hour)
	} else {
		expiresAt = partialUpload.CreatedAt.Add(time.Duration(partialUpload.ExpiresInHours) * time.Hour)
	}

	// Create file record in database
	// Always set maxDownloads (0 = unlimited, not "unset")
	maxDownloads := &partialUpload.MaxDownloads

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
		SHA256Hash:       sha256Hash,
	}

	if err := repos.Files.Create(ctx, fileRecord); err != nil {
		os.Remove(finalPath) // Clean up on error
		slog.Error("failed to create file record", "error", err, "upload_id", uploadID)
		repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to create file record: %v", err))
		return
	}

	// Mark partial upload as completed
	if err := repos.PartialUploads.SetAssemblyCompleted(ctx, uploadID, claimCode); err != nil {
		slog.Error("failed to mark partial upload as completed", "error", err, "upload_id", uploadID)
		// Don't fail the request - file is already created
	}

	// Delete chunks (cleanup)
	if err := utils.DeleteChunks(cfg.UploadDir, uploadID); err != nil {
		slog.Error("failed to delete chunks", "error", err, "upload_id", uploadID)
		// Don't fail - chunks will be cleaned up later by cleanup worker
	}

	// Emit webhook event for file upload completion
	EmitWebhookEvent(&webhooks.Event{
		Type:      webhooks.EventFileUploaded,
		Timestamp: time.Now(),
		File: webhooks.FileData{
			ID:        fileRecord.ID,
			ClaimCode: claimCode,
			Filename:  partialUpload.Filename,
			Size:      partialUpload.TotalSize,
			MimeType:  mimeType,
			ExpiresAt: expiresAt,
		},
	})

	slog.Info("async assembly completed successfully",
		"upload_id", uploadID,
		"claim_code", redactClaimCode(claimCode),
		"filename", partialUpload.Filename,
		"size", partialUpload.TotalSize,
		"total_chunks", partialUpload.TotalChunks,
		"password_protected", partialUpload.PasswordHash != "",
		"client_ip", clientIP,
	)
}
