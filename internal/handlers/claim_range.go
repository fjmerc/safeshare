package handlers

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

// serveFileWithRangeSupport handles serving a file with HTTP Range request support.
// This enables resumable downloads and partial content delivery for large files.
//
// Returns commitable=true when the response received the entire file (no Range
// header, or a Range covering [0, fileSize-1]) AND the stream completed
// successfully. The caller — ClaimHandler — uses this to decide between
// CommitDownload (counts toward max_downloads) and CancelDownload (does not).
// See ADR-012 §6 for the rationale.
func serveFileWithRangeSupport(
	w http.ResponseWriter,
	r *http.Request,
	file *models.File,
	filePath string,
	cfg *config.Config,
) (commitable bool) {
	// Check if file is stream-encrypted (SFSE1 or SFSE2 — same magic, distinguished by version byte).
	isStreamEnc, err := utils.IsStreamEncrypted(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Error("file not found on disk", "path", filePath, "claim_code", redactClaimCode(file.ClaimCode))
			sendErrorResponse(w, r, "File Not Found", "The file could not be found on the server. It may have been deleted. Please contact the administrator.", "NOT_FOUND", http.StatusNotFound)
			return false
		}
		slog.Error("failed to check file encryption format", "path", filePath, "error", err)
		sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
		return false
	}

	// Get the actual file size (decrypted size for encrypted files)
	fileSize := file.FileSize

	// Always advertise Range support
	w.Header().Set("Accept-Ranges", "bytes")

	// Check for Range header
	rangeHeader := r.Header.Get("Range")

	// Set common response headers
	w.Header().Set("Content-Type", file.MimeType)
	safeFilename := utils.SanitizeForContentDisposition(file.OriginalFilename)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, safeFilename))

	// If no Range header, serve the entire file
	if rangeHeader == "" {
		return serveEntireFile(w, r, file, filePath, cfg, isStreamEnc, fileSize)
	}

	// Parse Range header
	httpRange, err := utils.ParseRange(rangeHeader, fileSize)
	if err != nil {
		// Invalid range - return 416 Range Not Satisfiable
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
		slog.Warn("invalid range request",
			"claim_code", redactClaimCode(file.ClaimCode),
			"range_header", rangeHeader,
			"file_size", fileSize,
			"error", err,
			"client_ip", logIP(getClientIP(r), cfg),
		)
		sendErrorResponse(w, r, "Range Not Satisfiable", "The requested byte range is invalid or exceeds the file size.", "RANGE_NOT_SATISFIABLE", http.StatusRequestedRangeNotSatisfiable)
		return false
	}

	return servePartialContent(w, r, file, filePath, cfg, isStreamEnc, httpRange, fileSize)
}

// serveEntireFile serves the complete file without Range support (HTTP 200 OK).
// Returns commitable=true if the stream completed successfully — a full GET
// always counts as a download under ADR-012 Policy A.
func serveEntireFile(
	w http.ResponseWriter,
	r *http.Request,
	file *models.File,
	filePath string,
	cfg *config.Config,
	isStreamEnc bool,
	fileSize int64,
) (commitable bool) {
	var written int64

	// Handle streaming encrypted files (SFSE1 or SFSE2 via version-aware dispatcher).
	// SH-2.1 / ADR-011 §6: for SFSE2, pass the DB-recorded SHA-256 and plaintext
	// length so the post-decrypt integrity verify and header-length check actually
	// run on the full-file download path (start=0 .. end=fileSize-1 satisfies the
	// dispatcher's "fullRead" condition).
	if utils.IsEncryptionEnabled(cfg.EncryptionKey) && isStreamEnc {
		// Stream decrypt directly to response (no temp file)
		// Use optimized range decryption for the full file (0 to fileSize-1)
		// This enables immediate time-to-first-byte instead of waiting for full decryption
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))

		var err error
		written, err = utils.DecryptFileStreamingRangeAny(filePath, w, cfg.EncryptionKey, file.EncFileID, file.SHA256Hash, fileSize, 0, fileSize-1)
		if err != nil {
			slog.Error("failed to stream decrypt file", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
			// Can't send error response - headers already sent
			return false
		}
	} else {
		// Handle legacy encrypted format or non-encrypted files
		// Check if encryption is enabled and file might be legacy encrypted
		isLegacyEncrypted := false
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			// Read first 29 bytes to check for legacy encryption without loading entire file
			f, err := os.Open(filePath)
			if err != nil {
				if os.IsNotExist(err) {
					slog.Error("file not found on disk", "path", filePath, "claim_code", redactClaimCode(file.ClaimCode))
					sendErrorResponse(w, r, "File Not Found", "The file could not be found on the server. It may have been deleted. Please contact the administrator.", "NOT_FOUND", http.StatusNotFound)
					return
				}
				slog.Error("failed to open file", "path", filePath, "error", err)
				sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			header := make([]byte, 29)
			n, err := f.Read(header)
			f.Close()
			if err == nil && n == 29 && utils.IsEncrypted(header) {
				isLegacyEncrypted = true
			}
		}

		if isLegacyEncrypted {
			// Legacy encrypted file - must read entire file into memory to decrypt
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				slog.Error("failed to read encrypted file", "path", filePath, "error", err)
				sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
				return false
			}

			decrypted, err := utils.DecryptFile(fileData, cfg.EncryptionKey)
			if err != nil {
				// Normalize timing to prevent timing attacks that distinguish between:
				// - Authentication failures (wrong key)
				// - Format errors (invalid ciphertext)
				// - I/O errors (file read issues)
				time.Sleep(10 * time.Millisecond)
				slog.Error("failed to decrypt file", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				sendErrorResponse(w, r, "Decryption Error", "An error occurred while decrypting the file. Please contact the administrator.", "INTERNAL_ERROR", http.StatusInternalServerError)
				return false
			}

			// Write decrypted data to response
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(decrypted)))
			writtenInt, err := w.Write(decrypted)
			written = int64(writtenInt)
			if err != nil {
				slog.Error("failed to write file to response", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				return false
			}
		} else {
			// Non-encrypted file - use streaming to avoid loading entire file into memory
			f, err := os.Open(filePath)
			if err != nil {
				if os.IsNotExist(err) {
					slog.Error("file not found on disk", "path", filePath, "claim_code", redactClaimCode(file.ClaimCode))
					sendErrorResponse(w, r, "File Not Found", "The file could not be found on the server. It may have been deleted. Please contact the administrator.", "NOT_FOUND", http.StatusNotFound)
					return false
				}
				slog.Error("failed to open file", "path", filePath, "error", err)
				sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
				return false
			}
			defer f.Close()

			// Set Content-Length header
			w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))

			// Stream file directly to response
			written, err = io.Copy(w, f)
			if err != nil {
				slog.Error("failed to stream file to response", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				// Headers already sent, can't send error response
				return false
			}
		}
	}

	// Record metrics
	metrics.DownloadsTotal.WithLabelValues("success").Inc()
	metrics.DownloadSizeBytes.Observe(float64(written))

	// SH-2.3 / ADR-012: completed_downloads is incremented inside
	// FileRepository.CommitDownload (which the caller invokes when this function
	// returns commitable=true), keeping it lock-step with download_count. The
	// file.downloaded webhook is also emitted by the caller — only after Commit
	// has succeeded, so a Commit failure doesn't produce a phantom event.

	slog.Info("file downloaded (full)",
		"claim_code", redactClaimCode(file.ClaimCode),
		"filename", file.OriginalFilename,
		"size", written,
		"client_ip", logIP(getClientIP(r), cfg),
		"user_agent", getUserAgent(r),
	)
	return true
}

// servePartialContent serves a byte range from the file (HTTP 206 Partial Content).
//
// Under ADR-012 Policy A, a partial range commits the download reservation only
// if it happens to cover the entire file (Range: bytes=0-{fileSize-1} or
// equivalent). Tail probes, mid-file ranges, and 1-byte probes never commit.
func servePartialContent(
	w http.ResponseWriter,
	r *http.Request,
	file *models.File,
	filePath string,
	cfg *config.Config,
	isStreamEnc bool,
	httpRange *utils.HTTPRange,
	fileSize int64,
) (commitable bool) {
	// Set 206 Partial Content headers
	w.Header().Set("Content-Range", httpRange.ContentRangeHeader(fileSize))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", httpRange.ContentLength()))
	w.WriteHeader(http.StatusPartialContent)

	var written int64
	var err error

	// Range that covers the entire file behaves as a full download for accounting.
	fullCoverage := httpRange.Start == 0 && httpRange.End == fileSize-1

	// Handle streaming encrypted files (SFSE1 or SFSE2 via version-aware dispatcher).
	// SH-2.1 / ADR-011: pass expectedPlaintextLen so a header-length forgery is
	// caught even on partial-range reads. SHA-256 is only verified by the V2
	// reader when the range is in fact full-file; partial reads cannot validate
	// a whole-file digest so we pass "".
	if utils.IsEncryptionEnabled(cfg.EncryptionKey) && isStreamEnc {
		// For ranges that cover the entire file we pass the DB-recorded SHA-256 so the
		// SFSE2 post-decrypt verify runs (see ADR-011 §6); otherwise we cannot validate
		// a whole-file digest against a partial read.
		sha := ""
		if fullCoverage {
			sha = file.SHA256Hash
		}
		written, err = utils.DecryptFileStreamingRangeAny(filePath, w, cfg.EncryptionKey, file.EncFileID, sha, fileSize, httpRange.Start, httpRange.End)
		if err != nil {
			slog.Error("failed to decrypt file range", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
			// Can't send error response - headers already sent
			return false
		}
	} else {
		// Handle legacy encrypted format or non-encrypted files
		// Check if encryption is enabled and file might be legacy encrypted
		isLegacyEncrypted := false
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			// Read first 29 bytes to check for legacy encryption without loading entire file
			f, err := os.Open(filePath)
			if err != nil {
				slog.Error("failed to open file", "path", filePath, "error", err)
				// Can't send error response - headers already sent
				return
			}
			header := make([]byte, 29)
			n, err := f.Read(header)
			f.Close()
			if err == nil && n == 29 && utils.IsEncrypted(header) {
				isLegacyEncrypted = true
			}
		}

		if isLegacyEncrypted {
			// Legacy encrypted file - must read entire file into memory to decrypt
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				slog.Error("failed to read encrypted file", "path", filePath, "error", err)
				// Can't send error response - headers already sent
				return false
			}

			decrypted, err := utils.DecryptFile(fileData, cfg.EncryptionKey)
			if err != nil {
				// Normalize timing to prevent timing attacks that distinguish between error types
				time.Sleep(10 * time.Millisecond)
				slog.Error("failed to decrypt file", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				// Can't send error response - headers already sent
				return false
			}

			// Extract and write the requested range from decrypted data
			rangeData := decrypted[httpRange.Start : httpRange.End+1]
			writtenInt, err := w.Write(rangeData)
			written = int64(writtenInt)
			if err != nil {
				slog.Error("failed to write range to response", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				return false
			}
		} else {
			// Non-encrypted file - use streaming with seek to avoid loading entire file into memory
			f, err := os.Open(filePath)
			if err != nil {
				slog.Error("failed to open file", "path", filePath, "error", err)
				// Can't send error response - headers already sent
				return false
			}
			defer f.Close()

			// Seek to the start of the requested range
			_, err = f.Seek(httpRange.Start, io.SeekStart)
			if err != nil {
				slog.Error("failed to seek in file", "path", filePath, "offset", httpRange.Start, "error", err)
				return false
			}

			// Create a limited reader for the requested range
			limitedReader := io.LimitReader(f, httpRange.ContentLength())

			// Stream the range to response
			written, err = io.Copy(w, limitedReader)
			if err != nil {
				slog.Error("failed to stream range to response", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				return false
			}
		}
	}

	// Record metrics
	metrics.DownloadsTotal.WithLabelValues("success").Inc()
	metrics.DownloadSizeBytes.Observe(float64(written))

	slog.Info("file downloaded (partial)",
		"claim_code", redactClaimCode(file.ClaimCode),
		"filename", file.OriginalFilename,
		"range_start", httpRange.Start,
		"range_end", httpRange.End,
		"bytes_sent", written,
		"full_coverage", fullCoverage,
		"client_ip", logIP(getClientIP(r), cfg),
		"user_agent", getUserAgent(r),
	)
	return fullCoverage
}
