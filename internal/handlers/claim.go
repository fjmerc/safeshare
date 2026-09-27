package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/scanning"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// reservationFinalizeTimeout bounds the Commit/Cancel/Complete of a download
// session, which runs detached from the (possibly cancelled) request context.
// Long enough to cover beginImmediateTx's SQLITE_BUSY retries.
const reservationFinalizeTimeout = 30 * time.Second

// logTokenHash returns a short, non-reversible prefix for correlating log
// lines with the download_sessions row without ever writing the bearer
// token itself into logs (bug-hunter finding: the token is a bearer
// credential once ADR-014 lets it be replayed across requests). Matches the
// hash the repository layer stores, truncated to 8 hex chars — enough to
// eyeball-correlate a handful of log lines, not enough to be a lookup oracle.
func logTokenHash(token string) string {
	if token == "" || token == repository.ReservationTokenUnlimited {
		return token
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}

// ClaimHandler handles file download requests using claim codes
func ClaimHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// Accept GET (browser navigation / <a> tag) and POST (programmatic clients
		// that want to put the password in a form body instead of the URL).
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			sendErrorResponse(w, r, "Method Not Allowed", "This endpoint only accepts GET or POST requests.", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/claim/{code}
		path := r.URL.Path
		prefix := "/api/claim/"
		if !strings.HasPrefix(path, prefix) {
			sendErrorResponse(w, r, "Invalid URL", "The claim URL format is invalid. Please check the link and try again.", "INVALID_URL", http.StatusBadRequest)
			return
		}

		claimCode := strings.TrimPrefix(path, prefix)
		if claimCode == "" {
			sendErrorResponse(w, r, "Missing Claim Code", "No claim code was provided. Please check the link and try again.", "NO_CLAIM_CODE", http.StatusBadRequest)
			return
		}

		// Get file record from database
		file, err := repos.Files.GetByClaimCode(ctx, claimCode)
		if err != nil {
			slog.Error("failed to get file by claim code", "claim_code", redactClaimCode(claimCode), "error", err)
			sendErrorResponse(w, r, "Server Error", "An internal error occurred while retrieving the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if file == nil {
			// File not found or expired
			slog.Warn("file access denied",
				"reason", "not_found_or_expired",
				"claim_code", redactClaimCode(claimCode),
				"client_ip", logIP(getClientIP(r), cfg),
			)
			sendErrorResponse(w, r, "File Not Found or Expired", "This file does not exist or has expired. Files on SafeShare are automatically deleted after their expiration time. Please contact the sender if you need the file again.", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Block download of infected files
		if file.ScanStatus == scanning.ScanStatusInfected {
			slog.Warn("download blocked: file infected",
				"claim_code", redactClaimCode(claimCode),
				"virus_name", file.ScanResult,
				"client_ip", logIP(getClientIP(r), cfg),
			)
			sendErrorResponse(w, r, "File Quarantined",
				"This file was detected as malware and is not available for download.",
				"FILE_QUARANTINED", http.StatusGone)
			return
		}

		// Check password if file is password-protected.
		// SH-1.5: accept the password via three channels, in priority order:
		//   1. X-File-Password header — preferred; never lands in proxy logs,
		//      browser history, or outbound Referer.
		//   2. POST form body (`password`) — for programmatic clients that
		//      can't set custom headers but can POST a form.
		//   3. URL query string (`?password=…`) — deprecated; kept for one
		//      release to avoid breaking direct browser <a href> downloads
		//      while frontends migrate. Emits a WARN log + Deprecation
		//      response header so operators can see who still uses it.
		if utils.IsPasswordProtected(file.PasswordHash) {
			providedPassword, passwordViaQuery := extractDownloadPassword(w, r)

			if passwordViaQuery {
				// Defence-in-depth even on the deprecated path: tell the browser
				// not to forward the URL (which still contains the password) as a
				// Referer on any subsequent navigation triggered by the download
				// page.
				w.Header().Set("Referrer-Policy", "no-referrer")
				w.Header().Set("Deprecation", "true")
				w.Header().Set("Sunset", "Wed, 30 Sep 2026 00:00:00 GMT")
				// Points at a fetchable docs URL (RFC 8594 / draft-ietf-httpapi-
				// deprecation-header expect an actual resource, not a repo
				// path). Track this if the default branch is renamed.
				w.Header().Set("Link", `<https://github.com/fjmerc/safeshare/blob/main/docs/API_REFERENCE_FOR_TESTING.md#file-passwords-sh-15>; rel="deprecation"; type="text/markdown"`)
				slog.Warn("deprecated password-in-query-string usage",
					"claim_code", redactClaimCode(claimCode),
					"client_ip", logIP(getClientIP(r), cfg),
					"user_agent", getUserAgent(r),
				)
				metrics.DownloadsTotal.WithLabelValues("password_via_query_deprecated").Inc()
			}

			if !utils.VerifyPassword(file.PasswordHash, providedPassword) {
				metrics.DownloadsTotal.WithLabelValues("password_failed").Inc()

				slog.Warn("file access denied",
					"reason", "incorrect_password",
					"claim_code", redactClaimCode(claimCode),
					"filename", file.OriginalFilename,
					"client_ip", logIP(getClientIP(r), cfg),
					"user_agent", getUserAgent(r),
				)
				sendErrorResponse(w, r, "Incorrect Password", "The password provided for this file is incorrect. Please check the password and try again, or contact the sender for the correct password.", "INCORRECT_PASSWORD", http.StatusUnauthorized)
				return
			}
		}

		// SH-2.3 / ADR-012: download_count is no longer incremented up-front. The
		// race-fix property of the original TryIncrementDownloadWithLimit (P1) is
		// preserved by ReserveDownload, which takes an in_flight_reservations slot
		// against the same `(download_count + in_flight) < max_downloads` guard.

		// SH-2.3 bug-hunter M3: cap concurrent reservations per (file, IP) before
		// taking the DB-level slot. The global RateLimitDownload middleware bounds
		// total requests per IP per hour (default 50); this tracker bounds
		// *concurrency*, blocking a single attacker from burst-holding many slots
		// via slow reads on a max_downloads=N file. Disabled (cap == 0) bypasses
		// this entirely. Acquired here BEFORE Reserve so a 429 path doesn't touch
		// the reservation table at all.
		clientIPForCap := getClientIP(r)
		if !inFlightTracker.TryAcquire(file.ID, clientIPForCap) {
			slog.Warn("file access denied",
				"reason", "inflight_cap_per_ip_reached",
				"claim_code", redactClaimCode(claimCode),
				"file_id", file.ID,
				"client_ip", logIP(clientIPForCap, cfg),
				"max_per_ip", inFlightTracker.MaxPerIP(),
			)
			w.Header().Set("Retry-After", "120")
			sendErrorResponse(w, r,
				"Too Many Concurrent Downloads",
				"You have too many concurrent downloads in progress for this file. Please wait for them to finish and try again.",
				"TOO_MANY_INFLIGHT", http.StatusTooManyRequests)
			return
		}
		defer inFlightTracker.Release(file.ID, clientIPForCap)

		// Validate stored filename (defense-in-depth against database corruption/compromise)
		if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
			slog.Error("stored filename validation failed",
				"filename", file.StoredFilename,
				"error", err,
				"claim_code", redactClaimCode(claimCode),
				"client_ip", logIP(getClientIP(r), cfg),
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Read file from disk
		filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)

		// Store original claim code for optimistic locking
		originalClaimCode := file.ClaimCode

		// capped files (max_downloads set and > 0) go through the ADR-014
		// download-session flow below, which closes T1 (Range-splitting a
		// download never counted) and T5 (reaper TTL shorter than the max
		// transfer deadline). Uncapped files keep the original ADR-012 fast
		// path unchanged — see ADR-014 "Unlimited files keep the existing fast
		// path unchanged": no session bookkeeping, no X-Download-Session
		// header, no Cache-Control override, one code path fewer for the
		// overwhelmingly common case.
		capped := file.MaxDownloads != nil && *file.MaxDownloads > 0

		if !capped {
			// Reserve a download slot. ReserveDownload returns the sentinel
			// ReservationTokenUnlimited here; Commit/Cancel are no-ops for it.
			token, _, err := repos.Files.ReserveDownload(ctx, file.ID, originalClaimCode)
			if err != nil {
				if errors.Is(err, repository.ErrClaimCodeChanged) {
					slog.Warn("claim code changed before reservation",
						"file_id", file.ID,
						"original_code", redactClaimCode(originalClaimCode),
						"client_ip", logIP(getClientIP(r), cfg),
					)
					sendErrorResponse(w, r, "File Not Found or Expired", "This file does not exist or has expired. Files on SafeShare are automatically deleted after their expiration time. Please contact the sender if you need the file again.", "NOT_FOUND", http.StatusNotFound)
					return
				}
				slog.Error("failed to reserve download slot", "file_id", file.ID, "error", err)
				sendErrorResponse(w, r, "Server Error", "An internal error occurred while preparing the download. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			if token != "" && token != repository.ReservationTokenUnlimited {
				// Race: max_downloads was set on this file after we read it
				// (capped=false, from the snapshot at the top of this
				// handler), but ReserveDownload's fresh read saw the new cap
				// and returned a real session token instead of the sentinel.
				// Streaming it here would apply no probe threshold and never
				// Cancel on a partial range — release the slot and re-dispatch
				// to the capped flow, which re-reserves with the correct
				// threshold/session semantics (bug-hunter finding).
				if err := repos.Files.CancelDownload(ctx, file.ID, token); err != nil {
					slog.Error("failed to cancel late-capped reservation", "file_id", file.ID, "error", err)
				}
				// serveCappedDownload dereferences file.MaxDownloads once it
				// has credited a download — the `file` snapshot in scope here
				// still has it nil (that's the whole reason we're in this
				// branch), which would panic there. Re-read the file so the
				// capped flow sees the cap that's now actually in effect
				// (bug-hunter finding).
				freshFile, ferr := repos.Files.GetByID(ctx, file.ID)
				if ferr != nil || freshFile == nil {
					slog.Error("failed to re-read file for late-capped re-dispatch", "file_id", file.ID, "error", ferr)
					sendErrorResponse(w, r, "Server Error", "An internal error occurred while preparing the download. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
					return
				}
				serveCappedDownload(ctx, w, r, repos, cfg, freshFile, filePath, originalClaimCode, claimCode)
				return
			}

			// Serve file with Range support (handles both full and partial downloads).
			// Returns commitable=true only when the request received the entire file
			// (no Range header, or Range covering [0, fileSize-1]) AND the stream completed.
			extendTransferDeadline(w, cfg, file.FileSize)
			commitable := serveFileWithRangeSupport(w, r, file, filePath, cfg)

			// Commit/Cancel run on a context detached from the request: when the client
			// disconnects, r.Context() is already cancelled, the transaction can't begin.
			finalizeCtx, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), reservationFinalizeTimeout)
			defer cancelFinalize()

			committed := false
			if commitable {
				if err := repos.Files.CommitDownload(finalizeCtx, file.ID, token); err != nil {
					slog.Error("failed to commit download", "file_id", file.ID, "error", err)
				} else {
					committed = true
				}
			}
			// No cap, no reservation row for ReservationTokenUnlimited — nothing to
			// Cancel on the non-commitable path.

			if committed {
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
			}

			slog.Debug("download completed",
				"claim_code", redactClaimCode(claimCode),
				"committed", committed,
				"remaining_downloads", "unlimited",
			)
			return
		}

		// Capped files (max_downloads set and > 0) go through the ADR-014
		// download-session flow in claim_session.go, which closes T1
		// (Range-splitting a download never counted) and T5 (reaper TTL
		// shorter than the max transfer deadline).
		serveCappedDownload(ctx, w, r, repos, cfg, file, filePath, originalClaimCode, claimCode)
	}
}

// ClaimInfoHandler returns file information without downloading
func ClaimInfoHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// Only accept GET requests
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Extract claim code from URL path
		// Expected format: /api/claim/{code}/info
		path := r.URL.Path
		prefix := "/api/claim/"
		suffix := "/info"

		if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
			sendError(w, "Invalid claim URL", "INVALID_URL", http.StatusBadRequest)
			return
		}

		// Remove prefix and suffix to get claim code
		claimCode := strings.TrimPrefix(path, prefix)
		claimCode = strings.TrimSuffix(claimCode, suffix)

		if claimCode == "" {
			sendError(w, "Claim code required", "NO_CLAIM_CODE", http.StatusBadRequest)
			return
		}

		// Get file record from database
		file, err := repos.Files.GetByClaimCode(ctx, claimCode)
		if err != nil {
			slog.Error("failed to get file by claim code", "claim_code", redactClaimCode(claimCode), "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		if file == nil {
			// File not found or expired
			sendError(w, "File not found or expired", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Check download limit
		downloadLimitReached := false
		if file.MaxDownloads != nil && *file.MaxDownloads > 0 && file.DownloadCount >= *file.MaxDownloads {
			downloadLimitReached = true
		}

		// Build download URL
		downloadURL := buildDownloadURL(r, cfg, claimCode)

		// Return file info as JSON
		response := map[string]interface{}{
			"claim_code":             file.ClaimCode,
			"original_filename":      file.OriginalFilename,
			"file_size":              file.FileSize,
			"mime_type":              file.MimeType,
			"created_at":             file.CreatedAt,
			"expires_at":             file.ExpiresAt,
			"max_downloads":          file.MaxDownloads,
			"download_count":         file.DownloadCount,
			"completed_downloads":    file.CompletedDownloads,
			"download_limit_reached": downloadLimitReached,
			"password_required":      utils.IsPasswordProtected(file.PasswordHash),
			"download_url":           downloadURL,
			"sha256_hash":            file.SHA256Hash, // SHA256 checksum for client verification
			"client_encrypted":       file.ClientEncrypted,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

		slog.Info("file info retrieved",
			"claim_code", redactClaimCode(claimCode),
			"filename", file.OriginalFilename,
		)
	}
}

// extractDownloadPassword reads the file-download password from one of three
// channels in priority order: X-File-Password header, POST form body
// (`password`), then URL query string (`?password=…`). Returns the password
// and a flag indicating it came from the query string — the caller emits a
// deprecation warning + Referrer-Policy when that flag is set, since
// query-string transport leaks the secret to proxy logs, browser history,
// and outbound Referer headers.
//
// `w` is used to bound the size of POST bodies (passwords fit comfortably in
// 4 KiB; a multi-GB urlencoded body would otherwise stream into ParseForm and
// waste memory on an unauthenticated endpoint).
//
// See SH-1.5 in SafeShare-Planning/09-Security-Hardening/.
func extractDownloadPassword(w http.ResponseWriter, r *http.Request) (password string, viaQuery bool) {
	if h := r.Header.Get("X-File-Password"); h != "" {
		return h, false
	}
	if r.Method == http.MethodPost {
		// Gate to POST because PostFormValue reads only r.PostForm (which is
		// populated from a request body), never the URL query string —
		// otherwise a GET's `?password=` would be picked up here and silently
		// bypass the deprecation path. Cap the body at 4 KiB.
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err == nil {
			if v := r.PostFormValue("password"); v != "" {
				return v, false
			}
		}
	}
	if q := r.URL.Query().Get("password"); q != "" {
		return q, true
	}
	return "", false
}
