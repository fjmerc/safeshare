package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// bundleUploadTokenHeader carries the bearer token returned by
// POST /api/bundles. It authorizes adding members to, publishing and
// deleting that draft — and nothing else.
const bundleUploadTokenHeader = "X-Bundle-Upload-Token"

// maxBundleManifestBytes caps the opaque encrypted file list an E2E bundle stores.
// Sized for 100 files with 1 KB names (the longest a payload keeps), padded.
const maxBundleManifestBytes = 256 * 1024

var (
	errBundleNotFound      = errors.New("bundle not found")
	errBundlePositionTaken = errors.New("bundle position taken")
)

// hashBundleToken returns the hex SHA-256 of an upload token (what is stored).
func hashBundleToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newBundleUploadToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sameBundleOwner reports whether the caller may act on a draft: an
// anonymous bundle only from an anonymous caller, a user's bundle only
// from that user.
func sameBundleOwner(r *http.Request, b *models.Bundle) bool {
	user := middleware.GetUserFromContext(r)
	if b.UserID == nil {
		return user == nil
	}
	return user != nil && user.ID == *b.UserID
}

// authorizeDraft loads bundleID and checks it is an unexpired draft the
// caller owns, holding the matching upload token. Every failure is
// errBundleNotFound so a caller learns nothing about which check failed.
func authorizeDraft(ctx context.Context, r *http.Request, repos *repository.Repositories, bundleID int64) (*models.Bundle, error) {
	token := r.Header.Get(bundleUploadTokenHeader)
	if token == "" {
		return nil, errBundleNotFound
	}
	b, err := repos.Bundles.GetByID(ctx, bundleID)
	if err != nil {
		return nil, err
	}
	if b == nil || b.Status != models.BundleStatusDraft || !time.Now().Before(b.ExpiresAt) {
		return nil, errBundleNotFound
	}
	if subtle.ConstantTimeCompare([]byte(hashBundleToken(token)), []byte(b.UploadTokenHash)) != 1 {
		return nil, errBundleNotFound
	}
	if !sameBundleOwner(r, b) {
		return nil, errBundleNotFound
	}
	return b, nil
}

// resolveBundleMembership authorizes adding a member at position to bundleID.
func resolveBundleMembership(ctx context.Context, r *http.Request, repos *repository.Repositories, bundleID int64, position int) (*models.Bundle, error) {
	b, err := authorizeDraft(ctx, r, repos, bundleID)
	if err != nil {
		return nil, err
	}
	if position < 0 || position >= b.FileCount {
		return nil, errBundleNotFound
	}
	taken, err := repos.Bundles.MemberPositionTaken(ctx, bundleID, position)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, errBundlePositionTaken
	}
	return b, nil
}

// sendBundleMembershipError writes the response for a resolveBundleMembership failure.
func sendBundleMembershipError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBundleNotFound):
		sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
	case errors.Is(err, errBundlePositionTaken):
		sendError(w, "A file has already been uploaded at this position in the bundle", "BUNDLE_POSITION_TAKEN", http.StatusConflict)
	default:
		slog.Error("failed to resolve bundle membership", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
	}
}

// bundleMemberFromForm handles the bundle fields of a direct upload. It
// returns (nil, nil, true) for an ordinary upload, the bundle and position
// for an authorized member, or ok=false after writing an error. A request
// that carries any bundle field is treated as a member attempt and must
// pass every check (fail closed).
func bundleMemberFromForm(ctx context.Context, w http.ResponseWriter, r *http.Request, repos *repository.Repositories) (*models.Bundle, *int, bool) {
	idStr, posStr := r.FormValue("bundle_id"), r.FormValue("bundle_position")
	if idStr == "" && posStr == "" && r.Header.Get(bundleUploadTokenHeader) == "" {
		return nil, nil, true
	}
	bundleID, err1 := strconv.ParseInt(idStr, 10, 64)
	position, err2 := strconv.Atoi(posStr)
	if err1 != nil || err2 != nil {
		sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
		return nil, nil, false
	}
	b, err := resolveBundleMembership(ctx, r, repos, bundleID, position)
	if err != nil {
		sendBundleMembershipError(w, err)
		return nil, nil, false
	}
	return b, &position, true
}

// memberUploadParams builds a member's settings from its bundle. The
// request's own expiry/limit/password fields are ignored; only its
// client_encrypted declaration is read, and it must match the bundle's.
func memberUploadParams(w http.ResponseWriter, r *http.Request, b *models.Bundle, position int) (*uploadParams, bool) {
	clientEncrypted := clientEncryptedHeader(r)
	if v := r.FormValue("client_encrypted"); v == "true" || v == "1" {
		clientEncrypted = true
	}
	if clientEncrypted != b.ClientEncrypted {
		sendError(w, "client_encrypted must match the bundle", "INVALID_PARAMETER", http.StatusBadRequest)
		return nil, false
	}
	return &uploadParams{
		maxDownloads:    b.MaxDownloads,
		passwordHash:    b.PasswordHash,
		clientEncrypted: b.ClientEncrypted,
		bundle:          b,
		bundlePosition:  position,
	}, true
}

// publicBaseURL is the scheme://host (or PUBLIC_URL) links are built on.
func publicBaseURL(r *http.Request, cfg *config.Config) string {
	if cfg.PublicURL != "" {
		return strings.TrimSuffix(cfg.PublicURL, "/")
	}
	return getScheme(r) + "://" + getHost(r)
}

// BundleCreateHandler handles POST /api/bundles: create a draft bundle.
func BundleCreateHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}
		if utils.GetUploadTracker().IsShuttingDown() {
			sendError(w, "Server is shutting down, not accepting new uploads", "SERVICE_UNAVAILABLE", http.StatusServiceUnavailable)
			return
		}

		var req models.BundleCreateRequest
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendError(w, "Invalid JSON body", "INVALID_PARAMETER", http.StatusBadRequest)
			return
		}

		if cfg.IsClientEncryptionRequired() && !req.ClientEncrypted {
			rejectClientEncryptionRequired(w)
			return
		}
		if req.FileCount < 1 || req.FileCount > cfg.GetMaxFilesPerBundle() {
			sendError(w, fmt.Sprintf("file_count must be between 1 and %d", cfg.GetMaxFilesPerBundle()), "INVALID_PARAMETER", http.StatusBadRequest)
			return
		}
		if req.MaxDownloads < 0 {
			sendError(w, "Invalid max_downloads parameter", "INVALID_PARAMETER", http.StatusBadRequest)
			return
		}

		expiresAt := time.Now().Add(time.Duration(cfg.GetDefaultExpirationHours()) * time.Hour)
		if req.ExpiresInHours != nil {
			hours := *req.ExpiresInHours
			switch {
			case hours < 0:
				sendError(w, "Invalid expires_in_hours parameter", "INVALID_PARAMETER", http.StatusBadRequest)
				return
			case hours == 0:
				expiresAt = time.Now().Add(time.Duration(100*365*24) * time.Hour)
			case int(hours) > cfg.GetMaxExpirationHours():
				sendError(w,
					fmt.Sprintf("Expiration time exceeds maximum allowed (%d hours). Use 0 for files that never expire.", cfg.GetMaxExpirationHours()),
					"EXPIRATION_TOO_LONG", http.StatusBadRequest)
				return
			default:
				minutes := int(hours * 60)
				if minutes < 1 {
					minutes = 1
				}
				expiresAt = time.Now().Add(time.Duration(minutes) * time.Minute)
			}
		}

		bundle := &models.Bundle{
			Status:          models.BundleStatusDraft,
			FileCount:       req.FileCount,
			CreatedAt:       storeCreatedAt(cfg),
			ExpiresAt:       storeExpiry(expiresAt, cfg),
			ClientEncrypted: req.ClientEncrypted,
			UploaderIP:      storeIP(getClientIP(r), cfg),
		}
		if req.MaxDownloads > 0 {
			maxDL := req.MaxDownloads
			bundle.MaxDownloads = &maxDL
		}
		if req.Password != "" {
			hash, err := utils.HashPassword(req.Password)
			if err != nil {
				slog.Error("failed to hash bundle password", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			bundle.PasswordHash = hash
		}
		user := middleware.GetUserFromContext(r)
		if user != nil {
			uid := user.ID
			bundle.UserID = &uid
		}

		token, err := newBundleUploadToken()
		if err != nil {
			slog.Error("failed to generate bundle upload token", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		bundle.UploadTokenHash = hashBundleToken(token)

		created := false
		for attempt := 0; attempt < 5 && !created; attempt++ {
			code, err := utils.GenerateClaimCode()
			if err != nil {
				slog.Error("failed to generate bundle code", "error", err)
				break
			}
			bundle.BundleCode = code
			err = repos.Bundles.Create(ctx, bundle)
			if err == nil {
				created = true
			} else if !errors.Is(err, repository.ErrDuplicateKey) {
				slog.Error("failed to create bundle", "error", err)
				break
			}
		}
		if !created {
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		ev := audit.Event{Type: models.AuditEventFile, Action: "bundle_create", Outcome: models.AuditOutcomeSuccess,
			ResourceType: "bundle", ResourceID: idStr(bundle.ID),
			Details: map[string]any{"file_count": bundle.FileCount, "password_protected": bundle.PasswordHash != ""}}
		if user != nil {
			ev.UserID, ev.Username = user.ID, user.Username
		}
		audit.Record(r, cfg, ev)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.BundleCreateResponse{
			BundleID:    bundle.ID,
			BundleCode:  bundle.BundleCode,
			UploadToken: token,
			ExpiresAt:   bundle.ExpiresAt,
		})
	}
}

// BundleManageHandler routes /api/bundles/{id}/publish (POST) and
// /api/bundles/{id} (DELETE), both authorized by the draft's upload token.
func BundleManageHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/bundles/")
		idPart, action, _ := strings.Cut(rest, "/")
		bundleID, err := strconv.ParseInt(idPart, 10, 64)
		if err != nil || bundleID <= 0 {
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		switch {
		case action == "publish" && r.Method == http.MethodPost:
			publishBundle(w, r, repos, cfg, bundleID)
		case action == "" && r.Method == http.MethodDelete:
			deleteDraftBundle(w, r, repos, cfg, bundleID)
		case action == "publish" || action == "":
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		default:
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
		}
	}
}

func publishBundle(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, bundleID int64) {
	ctx := r.Context()
	bundle, err := authorizeDraft(ctx, r, repos, bundleID)
	if err != nil {
		sendBundleMembershipError(w, err)
		return
	}

	var req struct {
		EncryptedManifest string `json:"encrypted_manifest"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2*maxBundleManifestBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "Invalid JSON body", "INVALID_PARAMETER", http.StatusBadRequest)
		return
	}
	var manifest []byte
	if req.EncryptedManifest != "" {
		manifest, err = base64.StdEncoding.DecodeString(req.EncryptedManifest)
		if err != nil || len(manifest) == 0 || len(manifest) > maxBundleManifestBytes {
			sendError(w, "Invalid encrypted_manifest", "INVALID_PARAMETER", http.StatusBadRequest)
			return
		}
	}
	if bundle.ClientEncrypted != (manifest != nil) {
		sendError(w, "encrypted_manifest is required for end-to-end encrypted bundles and not allowed otherwise", "INVALID_PARAMETER", http.StatusBadRequest)
		return
	}

	if err := repos.Bundles.Publish(ctx, bundleID, manifest, storeCreatedAt(cfg)); err != nil {
		switch {
		case errors.Is(err, repository.ErrInvalidInput):
			sendError(w, "Not every file in the bundle has been uploaded and checked yet", "BUNDLE_INCOMPLETE", http.StatusConflict)
		case errors.Is(err, repository.ErrNotFound):
			sendError(w, "Bundle not found", "NOT_FOUND", http.StatusNotFound)
		default:
			slog.Error("failed to publish bundle", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		}
		return
	}

	members, err := repos.Bundles.ListMembers(ctx, bundleID)
	if err != nil {
		slog.Error("failed to list published bundle", "error", err)
		sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
		return
	}
	files := make([]models.BundleFileInfo, 0, len(members))
	for _, m := range members {
		files = append(files, models.BundleFileInfo{Position: *m.BundlePosition, Name: m.OriginalFilename, Size: m.FileSize, MimeType: m.MimeType})
	}

	ev := audit.Event{Type: models.AuditEventFile, Action: "bundle_publish", Outcome: models.AuditOutcomeSuccess,
		ResourceType: "bundle", ResourceID: idStr(bundleID), Details: map[string]any{"file_count": len(files)}}
	if user := middleware.GetUserFromContext(r); user != nil {
		ev.UserID, ev.Username = user.ID, user.Username
	}
	audit.Record(r, cfg, ev)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.BundleResponse{
		BundleCode:      bundle.BundleCode,
		BundleURL:       publicBaseURL(r, cfg) + "/#/bundle/" + bundle.BundleCode,
		ExpiresAt:       bundle.ExpiresAt,
		MaxDownloads:    bundle.MaxDownloads,
		ClientEncrypted: bundle.ClientEncrypted,
		Files:           files,
	})
}

func deleteDraftBundle(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, bundleID int64) {
	ctx := r.Context()
	if _, err := authorizeDraft(ctx, r, repos, bundleID); err != nil {
		sendBundleMembershipError(w, err)
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
	emitBundleFilesDeleted(deleted, "bundle discarded before it was published")

	ev := audit.Event{Type: models.AuditEventFile, Action: "bundle_delete", Outcome: models.AuditOutcomeSuccess,
		ResourceType: "bundle", ResourceID: idStr(bundleID), Details: map[string]any{"via": "upload_token", "file_count": len(deleted)}}
	if user := middleware.GetUserFromContext(r); user != nil {
		ev.UserID, ev.Username = user.ID, user.Username
	}
	audit.Record(r, cfg, ev)
	w.WriteHeader(http.StatusNoContent)
}

// emitBundleFilesDeleted sends a file.deleted webhook event for each file
// of a deleted bundle, as a single-file delete does.
func emitBundleFilesDeleted(files []*models.File, reason string) {
	for _, f := range files {
		r := reason
		EmitWebhookEvent(&webhooks.Event{
			Type:      webhooks.EventFileDeleted,
			Timestamp: time.Now(),
			File: webhooks.FileData{
				ID:        f.ID,
				ClaimCode: f.ClaimCode,
				Filename:  f.OriginalFilename,
				Size:      f.FileSize,
				Reason:    &r,
			},
		})
	}
}

// removeStoredFiles deletes the on-disk data of files whose rows are
// already gone. Errors are logged, not returned: the rows no longer exist,
// and the orphan sweep removes anything left behind.
func removeStoredFiles(cfg *config.Config, files []*models.File) {
	for _, f := range files {
		if err := utils.ValidateStoredFilename(f.StoredFilename); err != nil {
			slog.Error("refusing to remove file with invalid stored filename", "error", err)
			continue
		}
		path := filepath.Join(cfg.UploadDir, f.StoredFilename)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Error("failed to remove stored file", "path", path, "error", err)
		}
	}
}
