package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fjmerc/safeshare/internal/audit"
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

		// Enforced client-side encryption, early gate: reject BEFORE the body is
		// read (no multipart parsing, spooling to disk, quota checks or password
		// hashing) unless the request declares itself client-encrypted via the
		// header. The form field is still checked after parsing as a backstop.
		if cfg.IsClientEncryptionRequired() && !clientEncryptedHeader(r) {
			rejectClientEncryptionRequired(w)
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

		// Backstop for the early header gate above: the multipart form field
		// must also declare client_encrypted. By this point the body has been
		// parsed (and may be spooled), but nothing is stored yet.
		if rejectIfClientEncryptionRequired(w, cfg, params.clientEncrypted) {
			return
		}

		// ADR-015: when the operator has opted into rejecting uploads that
		// cannot be scanned at all (E2E ciphertext, or larger than the scanner's
		// size limit), fail fast before doing any other work.
		if cfg.Features.IsMalwareScanEnabled() && cfg.ClamAV.RejectUnscannable && isUnscannable(cfg, header.Size, params.clientEncrypted) {
			sendSmartError(w,
				"This file cannot be scanned for malware (it is end-to-end encrypted or exceeds the scan size limit) and this server rejects unscannable uploads",
				"UNSCANNABLE_UPLOAD", http.StatusUnprocessableEntity)
			return
		}

		// Generate unique claim code
		claimCode, err := generateUniqueClaimCode(ctx, w, repos)
		if err != nil {
			return // Error already sent to client
		}

		// ADR-015: scan the ORIGINAL uploaded bytes synchronously, before the
		// file is encrypted/stored and before the claim code is ever handed to
		// the client. The deadline is re-applied here so the scan (plus the
		// encryption/storage that follows it) gets the same size-proportional
		// budget as the initial upload did, plus the full CLAMAV_SCAN_TIMEOUT:
		// if the read deadline passed mid-scan, net/http would cancel the
		// request context and abort a slow-but-legitimate scan.
		var scanBudget time.Duration
		if cfg.Features.IsMalwareScanEnabled() {
			scanBudget = time.Duration(cfg.ClamAV.ScanTimeout)*time.Second + 30*time.Second
		}
		extendTransferDeadlineWithExtra(w, cfg, header.Size, scanBudget)
		verdict, scanErr := scanUpload(ctx, cfg, file, header.Size, params.clientEncrypted)
		if scanErr != nil {
			if !cfg.ClamAV.AllowUnverified {
				slog.Error("malware scan failed; rejecting upload (fail closed)",
					"error", scanErr,
					"filename", logFilename(header.Filename, cfg),
					"client_ip", logIP(getClientIP(r), cfg),
				)
				w.Header().Set("Retry-After", "30")
				sendSmartError(w, "Malware scanning is temporarily unavailable, please try again shortly", "SCAN_UNAVAILABLE", http.StatusServiceUnavailable)
				return
			}
			slog.Warn("malware scan failed; proceeding unverified (MALWARE_SCAN_ALLOW_UNVERIFIED)",
				"error", scanErr,
				"filename", logFilename(header.Filename, cfg),
			)
			verdict = scanVerdict{status: scanning.ScanStatusError, result: scanErr.Error()}
		}

		if verdict.status == scanning.ScanStatusInfected {
			recordInfectedUpload(ctx, repos, cfg, r, claimCode, header, params, verdict)
			sendSmartError(w, fmt.Sprintf("Malware detected: %s", verdict.result), "MALWARE_DETECTED", http.StatusUnprocessableEntity)
			return
		}

		// Rewind past the bytes scanUpload consumed so processAndStoreFile sees
		// the whole file from the start again.
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			slog.Error("failed to rewind upload after scan", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Process and store file
		result, err := processAndStoreFile(w, file, header, cfg)
		if err != nil {
			return // Error already sent to client
		}

		// TOCTOU defense in depth (bug-hunter finding): what was actually
		// stored must be exactly what was scanned. The plain upload path
		// reads both from the same multipart.File handle, so this should
		// never actually fire, but it costs nothing to verify and closes the
		// same class of bug on this path as the chunked one, should the
		// assumption ever stop holding (e.g. a future change re-reads from a
		// path instead of the handle). Compared BEFORE metadata stripping,
		// which intentionally changes the bytes.
		if verdict.hash != "" && verdict.hash != result.sha256Hash {
			os.Remove(result.filePath)
			slog.Error("stored content does not match scanned content; rejecting upload",
				"claim_code", redactClaimCode(claimCode),
				"filename", logFilename(header.Filename, cfg),
			)
			sendSmartError(w, "Upload could not be verified and was rejected", "INTEGRITY_MISMATCH", http.StatusInternalServerError)
			return
		}

		// Strip metadata if enabled and supported
		if cfg.IsStripMetadata() && privacy.SupportsMetadataStripping(result.detectedMimeType) {
			if err := stripMetadataFromUpload(result, cfg); err != nil {
				slog.Warn("failed to strip metadata",
					"error", err,
					"filename", logFilename(header.Filename, cfg),
					"mime_type", result.detectedMimeType,
				)
				if cfg.IsAnonymousMode() {
					// Fail closed: anonymous mode must not store a file whose
					// metadata could not be removed (includes files over the
					// stripper's size limit, which surface as an error here).
					os.Remove(result.filePath)
					sendSmartError(w, metadataStripFailedMessage, "METADATA_STRIP_FAILED", http.StatusUnprocessableEntity)
					return
				}
				// Non-fatal outside anonymous mode: continue with original file
			}
		}

		// Create database record and handle response
		createRecordAndRespond(ctx, w, r, repos, cfg, header, params, claimCode, result, quotaConfigured, verdict)
	}
}

// rejectIfClientEncryptionRequired sends a 400 CLIENT_ENCRYPTION_REQUIRED and
// returns true when the server requires client-side (E2E) encryption and the
// upload does not declare itself as client-encrypted.
//
// Honest limits: client_encrypted is an unauthenticated, client-declared flag;
// the server cannot see inside ciphertext and cannot verify it. This check
// protects honest uploaders (a stale cached page, a script, or a misconfigured
// client) from accidentally sending plaintext to a server that promised not to
// receive it. It is not a defence against a client that lies about the flag.
func rejectIfClientEncryptionRequired(w http.ResponseWriter, cfg *config.Config, clientEncrypted bool) bool {
	if !cfg.IsClientEncryptionRequired() || clientEncrypted {
		return false
	}
	rejectClientEncryptionRequired(w)
	return true
}

func rejectClientEncryptionRequired(w http.ResponseWriter) {
	sendSmartError(w,
		"This server only accepts files encrypted in your browser",
		"CLIENT_ENCRYPTION_REQUIRED",
		http.StatusBadRequest,
	)
}

// clientEncryptedHeaderName is sent by the web client on upload requests that
// carry client-side (E2E) ciphertext, so the server can refuse plaintext
// before reading the body. Like the form field it is a client declaration.
const clientEncryptedHeaderName = "X-SafeShare-Client-Encrypted"

func clientEncryptedHeader(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get(clientEncryptedHeaderName)), "true")
}

// isUnscannable reports whether an upload's content cannot be scanned at
// all: end-to-end encrypted (opaque ciphertext to the server) or larger than
// the configured scan size limit.
func isUnscannable(cfg *config.Config, size int64, clientEncrypted bool) bool {
	if clientEncrypted {
		return true
	}
	return cfg.ClamAV.MaxFileSize > 0 && size > cfg.ClamAV.MaxFileSize
}

// recordInfectedUpload writes a best-effort audit row for a rejected,
// infected upload: no file is ever written to disk and the claim code is
// never returned to the client. Insert failures are logged, not surfaced —
// the caller's 422 response to the client does not depend on this succeeding.
//
// Bug-hunter finding (post-ADR-015 review): the audit row must NOT be able
// to inflate quota/storage accounting. FileSize is recorded as 0 (the
// uploader's declared size never touched disk — it's logged and put on the
// webhook payload instead, for anyone who wants it), and the row gets a
// bounded expiry independent of what the uploader requested — in particular
// never "never expire" (expires_in_hours=0) — so repeated EICAR uploads
// can't permanently pin quota-counted rows. Defense in depth: the storage
// queries themselves (CreateWithQuotaCheck/GetTotalUsage/GetStats in both
// sqlite and postgres) additionally exclude scan_status='infected' rows.
func recordInfectedUpload(ctx context.Context, repos *repository.Repositories, cfg *config.Config, r *http.Request, claimCode string, header *multipart.FileHeader, params *uploadParams, verdict scanVerdict) {
	clientIP := getClientIP(r)

	var userID *int64
	if user := middleware.GetUserFromContext(r); user != nil {
		userID = &user.ID
	}

	// Bounded regardless of what the uploader asked for (params.neverExpire /
	// params.expiresInMinutes are deliberately ignored here) — this is an
	// audit record, not the file the uploader wanted.
	auditExpiresAt := time.Now().Add(time.Duration(cfg.GetDefaultExpirationHours()) * time.Hour)

	now := time.Now()
	sanitizedFilename := utils.SanitizeFilename(header.Filename)
	fileRecord := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: sanitizedFilename,
		// Placeholder to satisfy the NOT NULL column; no file is ever written
		// for an infected upload, and claim.go's scanGate blocks download by
		// scan_status before this path would ever be opened.
		StoredFilename: "quarantined-" + uuid.New().String(),
		// Never the uploader's declared size — see the doc comment above.
		FileSize:        0,
		MimeType:        "application/octet-stream",
		ExpiresAt:       auditExpiresAt,
		MaxDownloads:    params.maxDownloads,
		UploaderIP:      storeIP(clientIP, cfg),
		PasswordHash:    params.passwordHash,
		UserID:          userID,
		ClientEncrypted: params.clientEncrypted,
		ScanStatus:      verdict.status,
		ScanResult:      verdict.result,
		ScannedAt:       &now,
	}

	if err := repos.Files.Create(ctx, fileRecord); err != nil {
		metrics.MalwareAuditRecordFailuresTotal.Inc()
		slog.Error("failed to record infected upload audit row", "error", err, "claim_code", redactClaimCode(claimCode))
	}

	scanStatus := verdict.status
	scanResult := verdict.result
	EmitWebhookEvent(&webhooks.Event{
		Type:      webhooks.EventFileInfected,
		Timestamp: now,
		File: webhooks.FileData{
			ID:         fileRecord.ID,
			ClaimCode:  claimCode,
			Filename:   sanitizedFilename,
			Size:       header.Size, // declared size; nothing was actually stored
			ExpiresAt:  auditExpiresAt,
			ScanStatus: &scanStatus,
			ScanResult: &scanResult,
		},
	})

	infected := audit.Event{Type: models.AuditEventSecurity, Action: "malware_detected", Outcome: models.AuditOutcomeDenied,
		ResourceType: "file", Details: map[string]any{"virus_name": verdict.result, "filename": sanitizedFilename, "declared_size": header.Size}}
	if fileRecord.ID != 0 {
		infected.ResourceID = idStr(fileRecord.ID)
	}
	if user := middleware.GetUserFromContext(r); user != nil {
		infected.UserID, infected.Username = user.ID, user.Username
	}
	audit.Record(r, cfg, infected)

	slog.Warn("malware detected in upload; rejected before storage",
		"virus_name", verdict.result,
		"claim_code", redactClaimCode(claimCode),
		"filename", logFilename(sanitizedFilename, cfg),
		"declared_size", header.Size,
		"client_ip", logIP(clientIP, cfg),
	)
}

// validateAndGetUploadedFile validates the request and retrieves the uploaded file
func validateAndGetUploadedFile(w http.ResponseWriter, r *http.Request, cfg *config.Config) (_ multipart.File, _ *multipart.FileHeader, retErr error) {
	// Content-Length is -1 for chunked transfer encoding and is client-
	// controlled, so clamp to the configured maximum: an upload can never
	// legitimately exceed it (MaxBytesReader below enforces that), and a
	// forged huge Content-Length must not buy a longer deadline.
	expectedBytes := r.ContentLength
	if expectedBytes <= 0 || expectedBytes > cfg.GetMaxFileSize() {
		expectedBytes = cfg.GetMaxFileSize()
	}
	transferDeadline := extendTransferDeadline(w, cfg, expectedBytes)

	// The body is spooled to the upload volume below (not held in memory),
	// so check up front that it can fit there. This is best-effort: it only
	// covers a declared Content-Length (a chunked-encoding body is capped by
	// MaxBytesReader instead), and concurrent uploads each pass it on their
	// own. The caller's check after spooling is the real one - by then the
	// spooled copy is already on disk, so it asks for room for the stored
	// copy on top of it - and running out mid-spool fails with 507.
	if r.ContentLength > 0 {
		if err := checkStorageAvailability(w, r, cfg, expectedBytes, cfg.GetQuotaLimitGB() > 0); err != nil {
			return nil, nil, err
		}
	}

	// Stream the multipart body, spooling the file part to disk (T29).
	// A client that stops sending is cut off within about a minute instead
	// of holding its spool file until the full transfer deadline (T50).
	body := newIdleDeadlineReader(w, http.MaxBytesReader(w, r.Body, cfg.GetMaxFileSize()), transferDeadline)
	r.Body = body
	file, header, err := spoolUploadForm(r, "file", cfg.UploadDir)
	if err == nil {
		if err = body.drainRest(); err != nil {
			file.Close()
		}
	}
	body.finish(err)
	if err != nil {
		var spoolErr *spoolError
		switch {
		case isUploadTimeout(err):
			sendUploadTimeout(w, r)
		case errors.Is(err, syscall.ENOSPC):
			sendError(w, "Insufficient storage space", "INSUFFICIENT_STORAGE", http.StatusInsufficientStorage)
		case errors.As(err, &spoolErr):
			slog.Error("failed to spool upload", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		case errors.Is(err, errNoFormFile):
			sendError(w, "No file provided", "NO_FILE", http.StatusBadRequest)
		default:
			sendError(w, "File too large or invalid form data", "FILE_TOO_LARGE", http.StatusRequestEntityTooLarge)
		}
		return nil, nil, err
	}
	// The spooled file is an open descriptor: close it if any check below
	// rejects the upload (the caller only takes ownership on success).
	defer func() {
		if retErr != nil {
			file.Close()
		}
	}()

	// Validate filename for control characters (header injection prevention)
	if err := utils.ValidateUploadFilename(header.Filename); err != nil {
		clientIP := getClientIP(r)
		slog.Warn("rejected filename with control characters",
			"filename", logFilename(header.Filename, cfg),
			"error", err,
			"client_ip", logIP(clientIP, cfg),
		)
		sendError(w, "Invalid filename", "INVALID_FILENAME", http.StatusBadRequest)
		return nil, nil, err
	}

	// Validate file extension against the sanitized name, since that is the name
	// the file is stored and served under. Checking the raw name let
	// "payload.exe " through: its extension is ".exe ", and sanitizing
	// afterwards trimmed the space. Same order as the chunked init handler.
	allowed, blockedExt, err := utils.IsFileAllowed(utils.SanitizeFilename(header.Filename), cfg.GetBlockedExtensions())
	if err != nil {
		slog.Error("failed to validate file extension", "error", err)
		sendError(w, "Invalid filename", "INVALID_FILENAME", http.StatusBadRequest)
		return nil, nil, err
	}
	if !allowed {
		clientIP := getClientIP(r)
		slog.Warn("blocked file extension",
			"filename", logFilename(header.Filename, cfg),
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
	storedFilename := uuid.New().String() + filepath.Ext(utils.SanitizeFilename(header.Filename))

	// Create upload directory if it doesn't exist
	if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
		slog.Error("failed to create upload directory", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return nil, err
	}

	// Detect MIME type from file content
	detectedMimeType, fullReader, err := detectMimeTypeAndCreateReader(w, file, header, cfg)
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
func detectMimeTypeAndCreateReader(w http.ResponseWriter, file multipart.File, header *multipart.FileHeader, cfg *config.Config) (string, io.Reader, error) {
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
		"filename", logFilename(header.Filename, cfg),
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
			"filename", logFilename(header.Filename, cfg),
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

// createRecordAndRespond creates database record and sends response.
// verdict carries the ADR-015 synchronous scan outcome (already known not to
// be "infected" by the time this is called — see UploadHandler) and is
// persisted onto the file record; a zero verdict (scanning disabled) leaves
// the scan columns NULL.
func createRecordAndRespond(ctx context.Context, w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, header *multipart.FileHeader, params *uploadParams, claimCode string, result *fileProcessingResult, quotaConfigured bool, verdict scanVerdict) {
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
		SHA256Hash:       storeSHA256(result.sha256Hash, cfg),
		ClientEncrypted:  params.clientEncrypted,
		EncFileID:        result.encFileID,
	}
	if verdict.status != "" {
		now := time.Now()
		fileRecord.ScanStatus = verdict.status
		fileRecord.ScanResult = verdict.result
		fileRecord.ScannedAt = &now
	}

	// Create database record with quota check if needed
	if err := createFileRecord(ctx, w, repos, cfg, fileRecord, result.filePath, quotaConfigured, clientIP); err != nil {
		return
	}

	// Send success response and record metrics
	sendSuccessResponse(w, r, cfg, fileRecord, claimCode, result, sanitizedFilename, header, params.passwordHash, clientIP)
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

// sendSuccessResponse sends the upload success response and records metrics.
// The malware scan already ran synchronously (ADR-015) before this is
// called; fileRecord.ScanStatus already reflects its outcome.
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

	uploaded := audit.Event{Type: models.AuditEventFile, Action: "file_upload", Outcome: models.AuditOutcomeSuccess,
		ResourceType: "file", ResourceID: idStr(fileRecord.ID),
		Details: map[string]any{"filename": sanitizedFilename, "size": result.written, "password_protected": passwordHash != ""}}
	if user := middleware.GetUserFromContext(r); user != nil {
		uploaded.UserID, uploaded.Username = user.ID, user.Username
	}
	audit.Record(r, cfg, uploaded)

	slog.Info("file uploaded",
		"claim_code", redactClaimCode(claimCode),
		"filename", logFilename(header.Filename, cfg),
		"file_extension", utils.GetFileExtension(header.Filename),
		"size", result.written,
		"expires_at", fileRecord.ExpiresAt,
		"max_downloads", fileRecord.MaxDownloads,
		"password_protected", passwordHash != "",
		"scan_status", fileRecord.ScanStatus,
		"client_ip", logIP(clientIP, cfg),
		"user_agent", logUserAgent(getUserAgent(r), cfg),
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
