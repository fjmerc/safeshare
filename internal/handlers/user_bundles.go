package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type userBundleFile struct {
	Position           int    `json:"position"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	CompletedDownloads int    `json:"completed_downloads"`
}

type userBundle struct {
	ID                int64            `json:"id"`
	BundleCode        string           `json:"bundle_code"`
	CreatedAt         time.Time        `json:"created_at"`
	ExpiresAt         time.Time        `json:"expires_at"`
	MaxDownloads      *int             `json:"max_downloads"`
	PasswordProtected bool             `json:"password_protected"`
	ClientEncrypted   bool             `json:"client_encrypted"`
	FileCount         int              `json:"file_count"`
	TotalSize         int64            `json:"total_size"`
	Files             []userBundleFile `json:"files"`
}

// UserBundlesHandler serves the signed-in user's bundles:
//
//	GET    /api/user/bundles?limit=&offset=
//	DELETE /api/user/bundles/{id}
//	PUT    /api/user/bundles/{id}/expiration      {"new_expiration": RFC3339}
//	PUT    /api/user/bundles/{id}/regenerate-code
//	GET    /api/user/bundles/{id}/files/{position}/download (also HEAD; owner download, see owner_download.go)
//
// A bundle another user owns answers 404, like one that does not exist.
func UserBundlesHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.GetUserFromContext(r)
		if user == nil {
			sendError(w, "Unauthorized", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		// Only the exact route forms are served (no trailing slash, no extra
		// segments): the rate limiter matches these paths literally.
		rest := strings.TrimPrefix(r.URL.Path, "/api/user/bundles")
		if rest == "" || rest == "/" {
			if r.Method != http.MethodGet {
				sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
				return
			}
			listUserBundles(w, r, repos, user)
			return
		}

		idPart, action, hasAction := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
		bundleID, err := strconv.ParseInt(idPart, 10, 64)
		if err != nil || bundleID <= 0 || (hasAction && action == "") {
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		if strings.HasPrefix(action, "files/") {
			position, ok := memberDownloadPosition(action)
			if !ok {
				sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
			downloadUserBundleFile(w, r, repos, cfg, user, bundleID, position)
			return
		}
		if strings.Contains(action, "/") {
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		switch {
		case action == "" && r.Method == http.MethodDelete:
			deleteUserBundle(w, r, repos, cfg, user, bundleID)
		case action == "expiration" && r.Method == http.MethodPut:
			updateUserBundleExpiration(w, r, repos, cfg, user, bundleID)
		case action == "regenerate-code" && r.Method == http.MethodPut:
			regenerateUserBundleCode(w, r, repos, cfg, user, bundleID)
		case action == "" || action == "expiration" || action == "regenerate-code":
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		default:
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
		}
	}
}

func listUserBundles(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, user *models.User) {
	ctx := r.Context()
	limit, offset := 50, 0
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	bundles, total, err := repos.Bundles.ListByUser(ctx, user.ID, limit, offset)
	if err != nil {
		slog.Error("failed to list user bundles", "error", err, "user_id", user.ID)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	out := make([]userBundle, 0, len(bundles))
	for _, b := range bundles {
		members, err := repos.Bundles.ListMembers(ctx, b.ID)
		if err != nil {
			slog.Error("failed to list bundle members", "error", err, "bundle_id", b.ID)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		entry := userBundle{
			ID: b.ID, BundleCode: b.BundleCode, CreatedAt: b.CreatedAt, ExpiresAt: b.ExpiresAt,
			MaxDownloads: b.MaxDownloads, PasswordProtected: utils.IsPasswordProtected(b.PasswordHash),
			ClientEncrypted: b.ClientEncrypted, FileCount: len(members), Files: make([]userBundleFile, 0, len(members)),
		}
		for _, m := range members {
			entry.TotalSize += m.FileSize
			entry.Files = append(entry.Files, userBundleFile{
				Position: *m.BundlePosition, Name: m.OriginalFilename, Size: m.FileSize, CompletedDownloads: m.CompletedDownloads,
			})
		}
		out = append(out, entry)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"bundles": out,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// memberDownloadPosition parses "files/{position}/download".
func memberDownloadPosition(action string) (int, bool) {
	posStr, ok := strings.CutSuffix(strings.TrimPrefix(action, "files/"), ownerDownloadSuffix)
	if !ok || posStr == "" || strings.Contains(posStr, "/") {
		return 0, false
	}
	position, err := strconv.Atoi(posStr)
	if err != nil || position < 0 {
		return 0, false
	}
	return position, true
}

// downloadUserBundleFile serves one file of the user's own bundle to them
// (owner download: no password, not counted).
func downloadUserBundleFile(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, user *models.User, bundleID int64, position int) {
	w.Header().Set("Cache-Control", "private, no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	b, err := ownedPublishedBundle(ctx, repos, user, bundleID)
	if err != nil {
		slog.Error("failed to get bundle for owner download", "error", err, "bundle_id", bundleID)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if b == nil {
		sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
		return
	}
	if b.ClientEncrypted {
		sendError(w, "This bundle was encrypted in the browser; only its link can open it", "CLIENT_ENCRYPTED", http.StatusConflict)
		return
	}
	file, err := repos.Bundles.GetMember(ctx, b.ID, position)
	if err != nil {
		slog.Error("failed to get bundle member for owner download", "error", err, "bundle_id", bundleID)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if file == nil {
		sendError(w, "File not found", "NOT_FOUND", http.StatusNotFound)
		return
	}
	serveOwnerDownload(w, r, cfg, file, user)
}

// ownedPublishedBundle returns the bundle if user owns it and it is published.
func ownedPublishedBundle(ctx context.Context, repos *repository.Repositories, user *models.User, bundleID int64) (*models.Bundle, error) {
	b, err := repos.Bundles.GetByID(ctx, bundleID)
	if err != nil {
		return nil, err
	}
	if b == nil || b.UserID == nil || *b.UserID != user.ID || b.Status != models.BundleStatusPublished {
		return nil, nil
	}
	return b, nil
}

func deleteUserBundle(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, user *models.User, bundleID int64) {
	ctx := r.Context()
	b, err := ownedPublishedBundle(ctx, repos, user, bundleID)
	if err != nil {
		slog.Error("failed to load bundle", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	if b == nil {
		sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
		return
	}
	deleted, err := repos.Bundles.DeleteWithMembers(ctx, bundleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		slog.Error("failed to delete bundle", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	removeStoredFiles(cfg, deleted)
	emitBundleFilesDeleted(deleted, "bundle deleted by its owner")
	audit.Record(r, cfg, audit.Event{Type: models.AuditEventFile, Action: "bundle_delete", Outcome: models.AuditOutcomeSuccess,
		UserID: user.ID, Username: user.Username, ResourceType: "bundle", ResourceID: idStr(bundleID),
		Details: map[string]any{"via": "owner", "file_count": len(deleted)}})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "deleted_files": len(deleted)})
}

func updateUserBundleExpiration(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, user *models.User, bundleID int64) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		NewExpiration string `json:"new_expiration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid request format", "INVALID_PARAMETER", http.StatusBadRequest)
		return
	}
	newExpiration, err := time.Parse(time.RFC3339, req.NewExpiration)
	if err != nil {
		sendError(w, "Invalid date format", "INVALID_PARAMETER", http.StatusBadRequest)
		return
	}
	// Same rules as /api/user/files/update-expiration: year 9999 means never.
	isNeverExpire := newExpiration.Year() == 9999
	if !isNeverExpire && newExpiration.Before(time.Now()) {
		sendError(w, "Expiration date must be in the future", "INVALID_PARAMETER", http.StatusBadRequest)
		return
	}
	if !isNeverExpire && newExpiration.After(time.Now().Add(time.Duration(cfg.GetMaxExpirationHours())*time.Hour)) {
		sendError(w, fmt.Sprintf("Expiration cannot be more than %d hours from now", cfg.GetMaxExpirationHours()), "EXPIRATION_TOO_LONG", http.StatusBadRequest)
		return
	}

	if err := repos.Bundles.UpdateExpiration(r.Context(), bundleID, user.ID, storeExpiry(newExpiration, cfg)); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		slog.Error("failed to update bundle expiration", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	audit.Record(r, cfg, audit.Event{Type: models.AuditEventFile, Action: "bundle_update_expiration", Outcome: models.AuditOutcomeSuccess,
		UserID: user.ID, Username: user.Username, ResourceType: "bundle", ResourceID: idStr(bundleID)})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func regenerateUserBundleCode(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, user *models.User, bundleID int64) {
	ctx := r.Context()
	for attempt := 0; attempt < 5; attempt++ {
		code, err := utils.GenerateClaimCode()
		if err != nil {
			break
		}
		err = repos.Bundles.RegenerateCode(ctx, bundleID, user.ID, code)
		switch {
		case err == nil:
			audit.Record(r, cfg, audit.Event{Type: models.AuditEventFile, Action: "bundle_regenerate_code", Outcome: models.AuditOutcomeSuccess,
				UserID: user.ID, Username: user.Username, ResourceType: "bundle", ResourceID: idStr(bundleID)})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"bundle_code": code})
			return
		case errors.Is(err, repository.ErrNotFound):
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
			return
		case errors.Is(err, repository.ErrDuplicateKey):
			continue
		default:
			slog.Error("failed to regenerate bundle code", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
	}
	sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
}

// deleteBundleOfMember deletes, with all its files, the bundle that owns the
// file with claimCode. Admin tools address files by claim code; deleting
// one member removes the whole bundle so a bundle is never left with a
// hole. Reports whether claimCode belonged to a bundle.
func deleteBundleOfMember(ctx context.Context, r *http.Request, repos *repository.Repositories, cfg *config.Config, claimCode string) (bool, error) {
	bundleID, ok, err := repos.Bundles.BundleIDForMemberClaimCode(ctx, claimCode)
	if err != nil || !ok {
		return false, err
	}
	deleted, err := repos.Bundles.DeleteWithMembers(ctx, bundleID)
	if errors.Is(err, repository.ErrNotFound) {
		return true, nil // deleted concurrently
	}
	if err != nil {
		return true, err
	}
	removeStoredFiles(cfg, deleted)
	emitBundleFilesDeleted(deleted, "bundle deleted by admin")
	recordAdmin(r, cfg, audit.Event{Action: "bundle_delete", Outcome: models.AuditOutcomeSuccess,
		ResourceType: "bundle", ResourceID: idStr(bundleID), Details: map[string]any{"via": "admin", "file_count": len(deleted)}})
	slog.Info("admin deleted bundle", "bundle_id", bundleID, "files", len(deleted), "admin_ip", logIP(getClientIP(r), cfg))
	return true, nil
}
