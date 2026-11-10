package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// Owner downloads: a signed-in user downloading their own file from the
// dashboard. Unlike a claim, this needs no password and is not counted, so
// it still works after the file's download limit is reached and never uses
// up a download meant for the recipient. Everything else a claim enforces
// about the stored bytes still applies: the scan gate, the stored-path
// checks, decryption admission, Range handling and transfer deadlines.
//
//	GET|HEAD /api/user/files/{claimCode}/download
//	GET|HEAD /api/user/bundles/{id}/files/{position}/download (UserBundlesHandler)
//
// A file the user does not own answers 404, like one that does not exist.

const ownerDownloadSuffix = "/download"

// UserDownloadFileHandler serves GET|HEAD /api/user/files/{claimCode}/download.
func UserDownloadFileHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}
		user := middleware.GetUserFromContext(r)
		if user == nil {
			sendError(w, "Unauthorized", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		claimCode := extractClaimCodeFromPathWithSuffix(r.URL.Path, "/api/user/files/", ownerDownloadSuffix)
		if claimCode == "" || strings.Contains(claimCode, "/") || utils.ValidateClaimCode(claimCode) != nil {
			sendError(w, "File not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// GetByClaimCode leaves out expired files and bundle members.
		file, err := repos.Files.GetByClaimCode(r.Context(), claimCode)
		if err != nil {
			slog.Error("failed to get file for owner download", "claim_code", redactClaimCode(claimCode), "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if file == nil || file.UserID == nil || *file.UserID != user.ID {
			sendError(w, "File not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		serveOwnerDownload(w, r, cfg, file, user)
	}
}

// serveOwnerDownload streams a file to its owner: no password, no download
// reservation, no count, no webhook. The caller has checked ownership.
func serveOwnerDownload(w http.ResponseWriter, r *http.Request, cfg *config.Config, file *models.File, user *models.User) {
	w.Header().Set("Cache-Control", "private, no-store")

	// The server holds only ciphertext for a browser-encrypted file; the
	// key lives in the share link, so there is nothing useful to send.
	if file.ClientEncrypted {
		sendError(w, "This file was encrypted in the browser; only its share link can open it", "CLIENT_ENCRYPTED", http.StatusConflict)
		return
	}
	if !file.ExpiresAt.IsZero() && time.Now().After(file.ExpiresAt) {
		sendError(w, "File not found", "NOT_FOUND", http.StatusNotFound)
		return
	}

	// The same scan verdict a claim honours: a quarantined or unscanned
	// file is not served to its owner either.
	if gate := scanGate(file, cfg); gate.blocked {
		slog.Warn("owner download blocked by scan gate",
			"reason", gate.code,
			"claim_code", redactClaimCode(file.ClaimCode),
			"user_id", user.ID,
		)
		if gate.retryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(gate.retryAfter))
		}
		sendError(w, gate.message, gate.code, gate.statusCode)
		return
	}

	filePath, ok := resolveClaimFilePath(w, r, file, cfg)
	if !ok {
		return
	}

	if r.Method == http.MethodHead {
		serveFileWithRangeSupport(w, r, file, filePath, cfg, time.Time{})
		return
	}

	// Every GET is logged with who made it, a partial (Range) one too: this
	// path skips the password, the count and the webhook, so the audit log
	// is its record.
	transferDeadline := extendTransferDeadline(w, cfg, file.FileSize)
	complete := serveFileWithRangeSupport(w, r, file, filePath, cfg, transferDeadline)
	audit.Record(r, cfg, audit.Event{Type: models.AuditEventFile, Action: "file_download_owner", Outcome: models.AuditOutcomeSuccess,
		UserID: user.ID, Username: user.Username, ResourceType: "file", ResourceID: idStr(file.ID),
		Details: map[string]any{"complete": complete}})
}
