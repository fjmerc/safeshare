package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// serveFileWithRangeSupport handles serving a file with HTTP Range request support.
// This enables resumable downloads and partial content delivery for large files.
func serveFileWithRangeSupport(
	w http.ResponseWriter,
	r *http.Request,
	file *models.File,
	filePath string,
	cfg *config.Config,
	db *sql.DB,
) {
	// Check if file is stream-encrypted (SFSE1 format)
	isStreamEnc, err := utils.IsStreamEncrypted(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Error("file not found on disk", "path", filePath, "claim_code", redactClaimCode(file.ClaimCode))
			sendErrorResponse(w, r, "File Not Found", "The file could not be found on the server. It may have been deleted. Please contact the administrator.", "NOT_FOUND", http.StatusNotFound)
			return
		}
		slog.Error("failed to check file encryption format", "path", filePath, "error", err)
		sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
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
		serveEntireFile(w, r, file, filePath, cfg, isStreamEnc, fileSize, db)
		return
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
			"client_ip", getClientIP(r),
		)
		sendErrorResponse(w, r, "Range Not Satisfiable", "The requested byte range is invalid or exceeds the file size.", "RANGE_NOT_SATISFIABLE", http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// Serve partial content
	servePartialContent(w, r, file, filePath, cfg, isStreamEnc, httpRange, fileSize)
}

// serveEntireFile serves the complete file without Range support (HTTP 200 OK)
func serveEntireFile(
	w http.ResponseWriter,
	r *http.Request,
	file *models.File,
	filePath string,
	cfg *config.Config,
	isStreamEnc bool,
	fileSize int64,
	db *sql.DB,
) {
	var written int64

	// Handle streaming encrypted files
	if utils.IsEncryptionEnabled(cfg.EncryptionKey) && isStreamEnc {
		// Stream decrypt directly to response (no temp file)
		// Use optimized range decryption for the full file (0 to fileSize-1)
		// This enables immediate time-to-first-byte instead of waiting for full decryption
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))

		var err error
		written, err = utils.DecryptFileStreamingRange(filePath, w, cfg.EncryptionKey, 0, fileSize-1)
		if err != nil {
			slog.Error("failed to stream decrypt file", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
			// Can't send error response - headers already sent
			return
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
				return
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
				return
			}

			// Write decrypted data to response
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(decrypted)))
			writtenInt, err := w.Write(decrypted)
			written = int64(writtenInt)
			if err != nil {
				slog.Error("failed to write file to response", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				return
			}
		} else {
			// Non-encrypted file - use streaming to avoid loading entire file into memory
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
			defer f.Close()

			// Set Content-Length header
			w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))

			// Stream file directly to response
			written, err = io.Copy(w, f)
			if err != nil {
				slog.Error("failed to stream file to response", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				// Headers already sent, can't send error response
				return
			}
		}
	}

	// Record metrics
	metrics.DownloadsTotal.WithLabelValues("success").Inc()
	metrics.DownloadSizeBytes.Observe(float64(written))

	// Increment completed downloads counter (only for full file downloads, not ranges)
	if err := database.IncrementCompletedDownloads(db, file.ID); err != nil {
		slog.Error("failed to increment completed downloads", "file_id", file.ID, "error", err)
		// Don't fail the response - file was already successfully sent
	}

	// Emit webhook event for file download
	now := time.Now()
	EmitWebhookEvent(&webhooks.Event{
		Type:      webhooks.EventFileDownloaded,
		Timestamp: now,
		File: webhooks.FileData{
			ID:           file.ID,
			ClaimCode:    file.ClaimCode,
			Filename:     file.OriginalFilename,
			Size:         file.FileSize,
			MimeType:     file.MimeType,
			ExpiresAt:    file.ExpiresAt,
			DownloadedAt: &now,
		},
	})

	slog.Info("file downloaded (full)",
		"claim_code", redactClaimCode(file.ClaimCode),
		"filename", file.OriginalFilename,
		"size", written,
		"client_ip", getClientIP(r),
		"user_agent", getUserAgent(r),
	)
}

// servePartialContent serves a byte range from the file (HTTP 206 Partial Content)
func servePartialContent(
	w http.ResponseWriter,
	r *http.Request,
	file *models.File,
	filePath string,
	cfg *config.Config,
	isStreamEnc bool,
	httpRange *utils.HTTPRange,
	fileSize int64,
) {
	// Set 206 Partial Content headers
	w.Header().Set("Content-Range", httpRange.ContentRangeHeader(fileSize))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", httpRange.ContentLength()))
	w.WriteHeader(http.StatusPartialContent)

	var written int64
	var err error

	// Handle streaming encrypted files (optimized for ranges)
	if utils.IsEncryptionEnabled(cfg.EncryptionKey) && isStreamEnc {
		// Use optimized range decryption - only decrypt the chunks we need
		written, err = utils.DecryptFileStreamingRange(filePath, w, cfg.EncryptionKey, httpRange.Start, httpRange.End)
		if err != nil {
			slog.Error("failed to decrypt file range", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
			// Can't send error response - headers already sent
			return
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
				return
			}

			decrypted, err := utils.DecryptFile(fileData, cfg.EncryptionKey)
			if err != nil {
				// Normalize timing to prevent timing attacks that distinguish between error types
				time.Sleep(10 * time.Millisecond)
				slog.Error("failed to decrypt file", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				// Can't send error response - headers already sent
				return
			}

			// Extract and write the requested range from decrypted data
			rangeData := decrypted[httpRange.Start : httpRange.End+1]
			writtenInt, err := w.Write(rangeData)
			written = int64(writtenInt)
			if err != nil {
				slog.Error("failed to write range to response", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				return
			}
		} else {
			// Non-encrypted file - use streaming with seek to avoid loading entire file into memory
			f, err := os.Open(filePath)
			if err != nil {
				slog.Error("failed to open file", "path", filePath, "error", err)
				// Can't send error response - headers already sent
				return
			}
			defer f.Close()

			// Seek to the start of the requested range
			_, err = f.Seek(httpRange.Start, io.SeekStart)
			if err != nil {
				slog.Error("failed to seek in file", "path", filePath, "offset", httpRange.Start, "error", err)
				return
			}

			// Create a limited reader for the requested range
			limitedReader := io.LimitReader(f, httpRange.ContentLength())

			// Stream the range to response
			written, err = io.Copy(w, limitedReader)
			if err != nil {
				slog.Error("failed to stream range to response", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				return
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
		"client_ip", getClientIP(r),
		"user_agent", getUserAgent(r),
	)
}
