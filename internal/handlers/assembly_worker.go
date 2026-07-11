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
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/scanning"
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

	// Detect MIME type from the first chunk BEFORE assembly. The first 512
	// bytes of chunk 0 are identical to the assembled file's first 512 bytes,
	// and detecting up front lets the encrypted path below skip writing a
	// plaintext copy of the file entirely.
	mimeType := "application/octet-stream"
	{
		chunkFile, err := os.Open(utils.GetChunkPath(cfg.UploadDir, uploadID, 0))
		if err != nil {
			slog.Error("failed to open first chunk for MIME detection", "error", err, "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to open file for MIME detection: %v", err)); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		buffer := make([]byte, 512)
		n, err := chunkFile.Read(buffer)
		chunkFile.Close()

		if err != nil && err != io.EOF {
			slog.Error("failed to read first chunk for MIME detection", "error", err, "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to read file for MIME detection: %v", err)); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		detected := utils.DetectMimeType(buffer[:n])
		if detected != "" {
			mimeType = detected
		}
	}

	encryptionEnabled := utils.IsEncryptionEnabled(cfg.EncryptionKey)
	needsStrip := cfg.IsStripMetadata() && privacy.SupportsMetadataStripping(mimeType)
	scanEnabled := cfg.Features.IsMalwareScanEnabled()

	var totalBytesWritten int64
	var sha256Hash string
	var encFileID []byte
	var scan *scanVerdict

	// The fast path encrypts during assembly and never stages plaintext, so it
	// cannot be used when malware scanning is enabled (we must scan plaintext).
	if encryptionEnabled && !needsStrip && !scanEnabled {
		// Fast path: stream chunks through SHA-256 + SFSE2 encryption directly
		// into the final file. One read of the chunks, one write of the
		// ciphertext — no intermediate plaintext file (2 disk passes instead
		// of 4, and plaintext never touches the disk unchunked).
		var err error
		encFileID, err = utils.GenerateEncFileID()
		if err != nil {
			slog.Error("failed to generate enc_file_id", "error", err, "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to generate enc_file_id: %v", err)); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		totalBytesWritten, sha256Hash, err = utils.AssembleChunksEncrypted(
			cfg.UploadDir, uploadID, partialUpload.TotalChunks, partialUpload.TotalSize,
			finalPath, cfg.EncryptionKey, encFileID,
		)
		if err != nil {
			slog.Error("failed to assemble+encrypt chunks", "error", err, "upload_id", uploadID)
			os.Remove(finalPath) // defensive: AssembleChunksEncrypted removes on error, but be safe
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to assemble file: %v", err)); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}
	} else {
		// Multi-pass path: metadata stripping needs a plaintext file on disk,
		// and unencrypted deployments store the assembled file as-is.
		slog.Info("assembling chunks into final file",
			"upload_id", uploadID,
			"total_chunks", partialUpload.TotalChunks,
			"filename", partialUpload.Filename,
		)

		var err error
		totalBytesWritten, sha256Hash, err = utils.AssembleChunks(cfg.UploadDir, uploadID, partialUpload.TotalChunks, finalPath)
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

		// Strip metadata from assembled plaintext file (before encryption)
		if needsStrip {
			if err := privacy.StripFileMetadata(finalPath, mimeType); err != nil {
				slog.Warn("failed to strip metadata in chunked upload",
					"error", err,
					"upload_id", uploadID,
					"mime_type", mimeType,
				)
				// Non-fatal: continue with original file
			} else {
				// Recompute hash and size after stripping
				newHash, err := computeFileHash(finalPath)
				if err != nil {
					slog.Warn("failed to recompute hash after stripping", "error", err, "upload_id", uploadID)
				} else {
					sha256Hash = newHash
				}
				info, err := os.Stat(finalPath)
				if err != nil {
					slog.Warn("failed to stat file after stripping", "error", err, "upload_id", uploadID)
				} else {
					totalBytesWritten = info.Size()
				}
				slog.Info("metadata stripped from chunked upload",
					"upload_id", uploadID,
					"mime_type", mimeType,
					"file_size", totalBytesWritten,
				)
			}
		}

		// Scan the assembled PLAINTEXT before encryption. Scanning after
		// encryption would feed AES-GCM ciphertext to clamd, which never matches
		// signatures (the file would always read as "clean"). Runs synchronously
		// in this worker goroutine, so the verdict is known before the claim
		// code is created below — no download-before-verdict race.
		if scanEnabled {
			v := scanPlaintextFile(newConfiguredScanner(cfg), finalPath)
			scan = &v
		}

		// Encrypt if encryption is enabled (SFSE2). Skip encryption for an
		// infected file: it is recorded then deleted, so there is nothing worth
		// encrypting.
		if encryptionEnabled && (scan == nil || scan.Status != scanning.ScanStatusInfected) {
			slog.Debug("encrypting assembled file using SFSE2 streaming encryption", "upload_id", uploadID)

			var err error
			encFileID, err = utils.GenerateEncFileID()
			if err != nil {
				slog.Error("failed to generate enc_file_id", "error", err, "upload_id", uploadID)
				os.Remove(finalPath)
				if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to generate enc_file_id: %v", err)); setErr != nil {
					slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
				}
				return
			}

			// Encrypt to temporary file, then replace original.
			tempEncryptedPath := finalPath + ".encrypted.tmp"

			if err := utils.EncryptFileStreamingV2(finalPath, tempEncryptedPath, cfg.EncryptionKey, encFileID); err != nil {
				slog.Error("failed to encrypt file (SFSE2)", "error", err, "upload_id", uploadID)
				os.Remove(finalPath)
				os.Remove(tempEncryptedPath)
				if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to encrypt file: %v", err)); setErr != nil {
					slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
				}
				return
			}

			// Get file sizes for logging
			originalInfo, _ := os.Stat(finalPath)
			encryptedInfo, _ := os.Stat(tempEncryptedPath)

			// Replace original with encrypted version
			if err := os.Remove(finalPath); err != nil {
				slog.Error("failed to remove original file", "error", err, "upload_id", uploadID)
				os.Remove(tempEncryptedPath)
				if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to remove original file: %v", err)); setErr != nil {
					slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
				}
				return
			}
			if err := os.Rename(tempEncryptedPath, finalPath); err != nil {
				slog.Error("failed to rename encrypted file", "error", err, "upload_id", uploadID)
				os.Remove(tempEncryptedPath)
				if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to rename encrypted file: %v", err)); setErr != nil {
					slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
				}
				return
			}

			slog.Debug("file encrypted with SFSE2 streaming encryption",
				"upload_id", uploadID,
				"original_size", originalInfo.Size(),
				"encrypted_size", encryptedInfo.Size())
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
		FileSize:         totalBytesWritten,
		MimeType:         mimeType,
		ExpiresAt:        expiresAt,
		MaxDownloads:     maxDownloads,
		UploaderIP:       storeIP(clientIP, cfg),
		PasswordHash:     partialUpload.PasswordHash,
		UserID:           partialUpload.UserID,
		SHA256Hash:       sha256Hash,
		ClientEncrypted:  partialUpload.ClientEncrypted,
		EncFileID:        encFileID,
	}

	// Persist the scan verdict at creation time so the download gate has a
	// definitive status before the claim code is retrievable (no scan race).
	if scan != nil {
		fileRecord.ScanStatus = scan.Status
		fileRecord.ScanResult = scan.VirusName
	}

	if err := repos.Files.Create(ctx, fileRecord); err != nil {
		os.Remove(finalPath) // Clean up on error
		slog.Error("failed to create file record", "error", err, "upload_id", uploadID)
		if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to create file record: %v", err)); setErr != nil {
			slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
		}
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
			Size:      totalBytesWritten,
			MimeType:  mimeType,
			ExpiresAt: expiresAt,
		},
	})

	// Malware scanning (when enabled) already ran synchronously on the plaintext
	// above, and its verdict is persisted on the record. Infected files are
	// recorded (so the download gate reports them) then purged from disk and
	// announced via webhook. scanPlaintextFile/handleInfectedFile live in
	// upload.go (same package).
	if scan != nil && scan.Status == scanning.ScanStatusInfected {
		handleInfectedFile(fileRecord.ID, claimCode, partialUpload.Filename, totalBytesWritten,
			mimeType, expiresAt, scan.VirusName, finalPath)
	}

	slog.Info("async assembly completed successfully",
		"upload_id", uploadID,
		"claim_code", redactClaimCode(claimCode),
		"filename", partialUpload.Filename,
		"size", totalBytesWritten,
		"total_chunks", partialUpload.TotalChunks,
		"password_protected", partialUpload.PasswordHash != "",
		"client_ip", logIP(clientIP, cfg),
	)
}
