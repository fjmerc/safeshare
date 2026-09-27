package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/scanning"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
	"github.com/google/uuid"
)

// integrityMismatchMessage is the uploader-visible message when the
// scanned-vs-assembled content integrity check fails. Deliberately generic
// (L3 bug-hunter finding): it must not describe internal chunk paths or
// mechanics — those go to the server log instead, via logIntegrityMismatch.
const integrityMismatchMessage = "Upload could not be verified and was rejected"

// scannedContentMatches reports whether assembledHash matches what
// verdict.hash recorded during the scan. verdict.hash is empty when nothing
// meaningful was scanned (scanning disabled, or content skipped for size),
// in which case there is nothing to compare and the content is treated as
// matching.
func scannedContentMatches(verdict scanVerdict, assembledHash string) bool {
	return verdict.hash == "" || verdict.hash == assembledHash
}

// logIntegrityMismatch logs a scanned/assembled content mismatch at ERROR:
// this is a TOCTOU attack signature (bug-hunter finding), not a routine
// failure, and should be alerted on.
func logIntegrityMismatch(uploadID string) {
	slog.Error("scanned content does not match assembled content; rejecting upload (possible TOCTOU tampering)",
		"upload_id", uploadID,
	)
}

// scanRetryBackoff is the chunked-upload malware-scan retry schedule
// (ADR-015): a transient clamd hiccup during assembly gets three retries
// before the upload is failed (or, under MALWARE_SCAN_ALLOW_UNVERIFIED,
// waved through unverified). Assembly runs off the request path, so this
// can afford to wait longer than the simple upload path, which fails
// closed immediately with a client-retryable 503 instead.
var scanRetryBackoff = []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second}

// scanRetrySleep sleeps for d, waking early if the server begins shutting
// down (L3 bug-hunter finding: a plain time.Sleep ignored shutdown, needlessly
// holding an assembly-worker goroutine — and the assembly-slot semaphore it
// holds — open for up to 45s past a shutdown signal instead of letting the
// process exit promptly). Overridable in tests to avoid real delays.
var scanRetrySleep = func(d time.Duration) {
	select {
	case <-time.After(d):
	case <-utils.GetUploadTracker().ShutdownCh():
	}
}

// scanChunkedUploadWithRetry scans a chunked upload's assembled-but-not-yet-
// encrypted content straight off its chunk files (utils.OpenChunksReader),
// retrying scan errors (clamd unreachable, timed out, or an unparsable
// response — never an infected/clean verdict, which are not errors) per
// scanRetryBackoff. Each attempt opens a fresh chunk reader since a failed
// attempt may have partially consumed the previous one.
//
// A missing/unopenable chunk (utils.ErrChunkMissing) is NOT retried: the
// chunks are already frozen for assembly by this point, so a missing one
// means the data itself is gone or corrupted, not that clamd is
// unavailable — retrying three times with backoff would only delay an
// outcome that can't change, and the caller must not treat it as a
// SCAN_UNAVAILABLE/ALLOW_UNVERIFIED case (bug-hunter finding).
func scanChunkedUploadWithRetry(ctx context.Context, cfg *config.Config, uploadDir, uploadID string, totalChunks int, size int64, clientEncrypted bool) (scanVerdict, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		reader := utils.OpenChunksReader(uploadDir, uploadID, totalChunks)
		verdict, err := scanUpload(ctx, cfg, reader, size, clientEncrypted)
		if closeErr := reader.Close(); closeErr != nil {
			slog.Warn("failed to close chunk reader after scan", "error", closeErr, "upload_id", uploadID)
		}
		if err == nil {
			return verdict, nil
		}
		if errors.Is(err, utils.ErrChunkMissing) {
			return scanVerdict{}, err
		}
		if !errors.Is(err, scanning.ErrConnect) {
			// Not a connection blip: a scan timeout or a clamd ERROR reply
			// will just recur identically on an immediate retry against the
			// same clamd, so retrying only wastes an assembly-worker slot for
			// up to the full backoff schedule (bug-hunter finding) — and,
			// under MALWARE_SCAN_ALLOW_UNVERIFIED, gives an uploader who can
			// deliberately trigger a clamd-side error (e.g. a crafted stream)
			// a way to reliably wait out "unavailable" faster.
			return scanVerdict{}, err
		}
		lastErr = err
		if attempt >= len(scanRetryBackoff) {
			return scanVerdict{}, lastErr
		}
		backoff := scanRetryBackoff[attempt]
		slog.Warn("malware scan connection failed; retrying",
			"error", err,
			"upload_id", uploadID,
			"attempt", attempt+1,
			"backoff", backoff,
		)
		scanRetrySleep(backoff)
		if utils.GetUploadTracker().IsShuttingDown() {
			return scanVerdict{}, errScanInterruptedByShutdown
		}
	}
}

// errScanInterruptedByShutdown means the server began shutting down while a
// scan was waiting to retry. The upload is neither failed nor published; it
// stays in "processing" for the assembly recovery worker to re-run.
var errScanInterruptedByShutdown = errors.New("malware scan interrupted by shutdown")

// recordInfectedChunkedUpload writes a best-effort audit row for a
// rejected, infected chunked upload: no assembled file is ever written and
// claimCode is never surfaced through the status endpoint (SetAssemblyFailed
// leaves partial_uploads.claim_code unset). Insert failures are logged, not
// surfaced — the caller marks assembly failed regardless.
//
// Bug-hunter finding (post-ADR-015 review): see recordInfectedUpload's doc
// comment in upload.go — the same quota/storage-inflation fix applies here:
// FileSize is 0, and the audit row's expiry is bounded to the server's
// default regardless of what the uploader requested (including
// expires_in_hours=0, "never expire").
func recordInfectedChunkedUpload(ctx context.Context, repos *repository.Repositories, cfg *config.Config, partialUpload *models.PartialUpload, claimCode, clientIP string, verdict scanVerdict) {
	auditExpiresAt := time.Now().Add(time.Duration(cfg.GetDefaultExpirationHours()) * time.Hour)

	now := time.Now()
	fileRecord := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: partialUpload.Filename,
		// Placeholder to satisfy the NOT NULL column; no file is ever
		// assembled for an infected upload, and claim.go's scanGate blocks
		// download by scan_status before this path would ever be opened.
		StoredFilename: "quarantined-" + uuid.New().String(),
		// Never the uploader's declared size — see the doc comment above.
		FileSize:        0,
		MimeType:        "application/octet-stream",
		ExpiresAt:       auditExpiresAt,
		MaxDownloads:    &partialUpload.MaxDownloads,
		UploaderIP:      storeIP(clientIP, cfg),
		PasswordHash:    partialUpload.PasswordHash,
		UserID:          partialUpload.UserID,
		ClientEncrypted: partialUpload.ClientEncrypted,
		ScanStatus:      verdict.status,
		ScanResult:      verdict.result,
		ScannedAt:       &now,
	}

	if err := repos.Files.Create(ctx, fileRecord); err != nil {
		metrics.MalwareAuditRecordFailuresTotal.Inc()
		slog.Error("failed to record infected chunked upload audit row", "error", err, "upload_id", partialUpload.UploadID)
	}

	scanStatus := verdict.status
	scanResult := verdict.result
	EmitWebhookEvent(&webhooks.Event{
		Type:      webhooks.EventFileInfected,
		Timestamp: now,
		File: webhooks.FileData{
			ID:         fileRecord.ID,
			ClaimCode:  claimCode,
			Filename:   partialUpload.Filename,
			Size:       partialUpload.TotalSize, // declared size; nothing was actually stored
			ExpiresAt:  auditExpiresAt,
			ScanStatus: &scanStatus,
			ScanResult: &scanResult,
		},
	})
}

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
			if err := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Assembly panicked: %v", r), ""); err != nil {
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
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to generate claim code: %v", err), ""); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		// Check if code already exists
		existing, err := repos.Files.GetByClaimCode(ctx, claimCode)
		if err != nil {
			slog.Error("failed to check claim code", "error", err, "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to check claim code: %v", err), ""); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		if existing == nil {
			break // Code is unique
		}

		if i == maxRetries-1 {
			slog.Error("failed to generate unique claim code after retries", "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, "Failed to generate unique claim code", ""); setErr != nil {
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
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to open file for MIME detection: %v", err), ""); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		buffer := make([]byte, 512)
		n, err := chunkFile.Read(buffer)
		chunkFile.Close()

		if err != nil && err != io.EOF {
			slog.Error("failed to read first chunk for MIME detection", "error", err, "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to read file for MIME detection: %v", err), ""); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		detected := utils.DetectMimeType(buffer[:n])
		if detected != "" {
			mimeType = detected
		}
	}

	// ADR-015: scan the chunk content synchronously, straight off the chunk
	// files, before any encryption/strip/storage work below — a rejected
	// upload must never reach the assemble/encrypt branch or produce a
	// stored file.
	verdict, scanErr := scanChunkedUploadWithRetry(ctx, cfg, cfg.UploadDir, uploadID, partialUpload.TotalChunks, partialUpload.TotalSize, partialUpload.ClientEncrypted)
	if scanErr != nil {
		// A missing/unopenable chunk is an assembly problem, not a scan
		// verification problem: MALWARE_SCAN_ALLOW_UNVERIFIED must not apply
		// (there's nothing to "proceed unverified" with — the data is gone),
		// and it gets its own error_code rather than SCAN_UNAVAILABLE
		// (bug-hunter finding).
		if errors.Is(scanErr, errScanInterruptedByShutdown) {
			// Leave the upload in "processing", exactly as a crash would:
			// the assembly recovery worker re-runs it (and rescans) after
			// restart. Failing it here would discard a good upload, and
			// publishing it unverified would skip the scan.
			slog.Warn("malware scan interrupted by shutdown; leaving upload for recovery", "upload_id", uploadID)
			return
		}
		if errors.Is(scanErr, utils.ErrChunkMissing) {
			// Full error (which includes the internal chunk file path) goes
			// to the log only — the uploader-visible error_message must stay
			// generic (L3 bug-hunter finding: no internal filesystem layout
			// in client-facing text).
			slog.Error("failed to read uploaded chunks for malware scan; failing assembly",
				"error", scanErr,
				"upload_id", uploadID,
			)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, "Failed to read uploaded file data", "ASSEMBLY_FAILED"); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}
		if !cfg.ClamAV.AllowUnverified {
			slog.Error("malware scan failed after retries; failing assembly (fail closed)",
				"error", scanErr,
				"upload_id", uploadID,
			)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, "Malware scanning is temporarily unavailable", "SCAN_UNAVAILABLE"); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}
		slog.Warn("malware scan failed after retries; proceeding unverified (MALWARE_SCAN_ALLOW_UNVERIFIED)",
			"error", scanErr,
			"upload_id", uploadID,
		)
		verdict = scanVerdict{status: scanning.ScanStatusError, result: scanErr.Error()}
	}

	if verdict.status == scanning.ScanStatusInfected {
		slog.Warn("malware detected in chunked upload; rejecting before assembly",
			"virus_name", verdict.result,
			"upload_id", uploadID,
		)
		recordInfectedChunkedUpload(ctx, repos, cfg, partialUpload, claimCode, clientIP, verdict)
		if err := utils.DeleteChunks(cfg.UploadDir, uploadID); err != nil {
			slog.Error("failed to delete chunks for infected upload", "error", err, "upload_id", uploadID)
		}
		if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Upload rejected: malware detected (%s)", verdict.result), "MALWARE_DETECTED"); setErr != nil {
			slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
		}
		return
	}

	encryptionEnabled := utils.IsEncryptionEnabled(cfg.EncryptionKey)
	needsStrip := cfg.IsStripMetadata() && privacy.SupportsMetadataStripping(mimeType)

	var totalBytesWritten int64
	var sha256Hash string
	var encFileID []byte

	if encryptionEnabled && !needsStrip {
		// Fast path: stream chunks through SHA-256 + SFSE2 encryption directly
		// into the final file. One read of the chunks, one write of the
		// ciphertext — no intermediate plaintext file (2 disk passes instead
		// of 4, and plaintext never touches the disk unchunked).
		var err error
		encFileID, err = utils.GenerateEncFileID()
		if err != nil {
			slog.Error("failed to generate enc_file_id", "error", err, "upload_id", uploadID)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to generate enc_file_id: %v", err), ""); setErr != nil {
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
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to assemble file: %v", err), ""); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		if !scannedContentMatches(verdict, sha256Hash) {
			logIntegrityMismatch(uploadID)
			os.Remove(finalPath)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, integrityMismatchMessage, "ASSEMBLY_FAILED"); setErr != nil {
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
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to assemble file: %v", err), ""); setErr != nil {
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
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Assembled file size mismatch: expected %d, got %d", partialUpload.TotalSize, totalBytesWritten), ""); setErr != nil {
				slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
			}
			return
		}

		// TOCTOU integrity check (bug-hunter finding): a chunk on disk can be
		// rewritten between the synchronous scan (which read the chunk files
		// once, sequentially) and this assembly step (which reopens them from
		// the same paths) — e.g. re-uploading chunk 0 with different, same-
		// size content while racing /complete. Compared BEFORE metadata
		// stripping, which intentionally changes the bytes; see verdict.hash's
		// doc comment for what's covered.
		if !scannedContentMatches(verdict, sha256Hash) {
			logIntegrityMismatch(uploadID)
			os.Remove(finalPath)
			if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, integrityMismatchMessage, "ASSEMBLY_FAILED"); setErr != nil {
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

		// Encrypt if encryption is enabled (SFSE2)
		if encryptionEnabled {
			slog.Debug("encrypting assembled file using SFSE2 streaming encryption", "upload_id", uploadID)

			var err error
			encFileID, err = utils.GenerateEncFileID()
			if err != nil {
				slog.Error("failed to generate enc_file_id", "error", err, "upload_id", uploadID)
				os.Remove(finalPath)
				if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to generate enc_file_id: %v", err), ""); setErr != nil {
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
				if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to encrypt file: %v", err), ""); setErr != nil {
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
				if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to remove original file: %v", err), ""); setErr != nil {
					slog.Error("failed to mark assembly as failed", "error", setErr, "upload_id", uploadID)
				}
				return
			}
			if err := os.Rename(tempEncryptedPath, finalPath); err != nil {
				slog.Error("failed to rename encrypted file", "error", err, "upload_id", uploadID)
				os.Remove(tempEncryptedPath)
				if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to rename encrypted file: %v", err), ""); setErr != nil {
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
	if verdict.status != "" {
		scannedAt := time.Now()
		fileRecord.ScanStatus = verdict.status
		fileRecord.ScanResult = verdict.result
		fileRecord.ScannedAt = &scannedAt
	}

	if err := repos.Files.Create(ctx, fileRecord); err != nil {
		os.Remove(finalPath) // Clean up on error
		slog.Error("failed to create file record", "error", err, "upload_id", uploadID)
		if setErr := repos.PartialUploads.SetAssemblyFailed(ctx, uploadID, fmt.Sprintf("Failed to create file record: %v", err), ""); setErr != nil {
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

	slog.Info("async assembly completed successfully",
		"upload_id", uploadID,
		"claim_code", redactClaimCode(claimCode),
		"filename", partialUpload.Filename,
		"size", totalBytesWritten,
		"total_chunks", partialUpload.TotalChunks,
		"password_protected", partialUpload.PasswordHash != "",
		"scan_status", fileRecord.ScanStatus,
		"client_ip", logIP(clientIP, cfg),
	)
}
