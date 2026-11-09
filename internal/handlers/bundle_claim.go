package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/fjmerc/safeshare/internal/claimcode"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// The not-found responses below are byte-identical to what /api/claim/
// sends for an unknown code, so a recipient (or a code guesser) cannot
// tell an unknown, draft, expired or deleted bundle apart — from each
// other or from a missing single file.

func sendBundleInfoNotFound(w http.ResponseWriter) {
	sendError(w, "File not found or expired", "NOT_FOUND", http.StatusNotFound)
}

func sendBundleFileNotFound(w http.ResponseWriter, r *http.Request) {
	sendErrorResponse(w, r, "File Not Found or Expired", "This file does not exist or has expired. Files on SafeShare are automatically deleted after their expiration time. Please contact the sender if you need the file again.", "NOT_FOUND", http.StatusNotFound)
}

// BundleInfoHandler handles GET /api/bundle/{code}/info: the bundle's
// settings and its files' details. Like /api/claim/{code}/info it needs no
// password, and it never includes the members' own claim codes.
func BundleInfoHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w.Header().Set("Cache-Control", "private, no-store")
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		code := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/bundle/"), "/info")
		if !claimcode.Valid(code) {
			sendBundleInfoNotFound(w)
			return
		}
		bundle, err := repos.Bundles.GetPublishedByCode(ctx, code)
		if err != nil {
			slog.Error("failed to get bundle", "bundle_code", redactClaimCode(code), "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if bundle == nil {
			sendBundleInfoNotFound(w)
			return
		}
		members, err := repos.Bundles.ListMembers(ctx, bundle.ID)
		if err != nil {
			slog.Error("failed to list bundle members", "bundle_code", redactClaimCode(code), "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if len(members) == 0 {
			sendBundleInfoNotFound(w)
			return
		}

		files := make([]map[string]interface{}, 0, len(members))
		for _, m := range members {
			entry := claimInfoPayload(r, cfg, m)
			delete(entry, "claim_code")
			delete(entry, "download_url")
			entry["position"] = *m.BundlePosition
			files = append(files, entry)
		}

		response := map[string]interface{}{
			"bundle_code":       bundle.BundleCode,
			"expires_at":        bundle.ExpiresAt,
			"file_count":        len(files),
			"max_downloads":     bundle.MaxDownloads,
			"password_required": utils.IsPasswordProtected(bundle.PasswordHash),
			"client_encrypted":  bundle.ClientEncrypted,
			"files":             files,
		}
		if len(bundle.EncryptedManifest) > 0 {
			response["encrypted_manifest"] = bundle.EncryptedManifest // []byte encodes as base64
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// BundleFileHandler handles GET/HEAD/POST /api/bundle/{code}/files/{position}:
// one member's bytes, through exactly the pipeline /api/claim/{code} uses
// (scan gate, password, download limit and ADR-014 sessions, Range).
func BundleFileHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w.Header().Set("Cache-Control", "private, no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
			sendErrorResponse(w, r, "Method Not Allowed", "This endpoint only accepts GET, POST, or HEAD requests.", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		rest := strings.TrimPrefix(r.URL.Path, "/api/bundle/")
		code, posStr, ok := strings.Cut(rest, "/files/")
		position, err := strconv.Atoi(posStr)
		if !ok || err != nil || position < 0 || !claimcode.Valid(code) {
			sendBundleFileNotFound(w, r)
			return
		}

		bundle, err := repos.Bundles.GetPublishedByCode(ctx, code)
		if err != nil {
			slog.Error("failed to get bundle", "bundle_code", redactClaimCode(code), "error", err)
			sendErrorResponse(w, r, "Server Error", "An internal error occurred while retrieving the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if bundle == nil {
			sendBundleFileNotFound(w, r)
			return
		}
		file, err := repos.Bundles.GetMember(ctx, bundle.ID, position)
		if err != nil {
			slog.Error("failed to get bundle member", "bundle_code", redactClaimCode(code), "error", err)
			sendErrorResponse(w, r, "Server Error", "An internal error occurred while retrieving the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if file == nil {
			sendBundleFileNotFound(w, r)
			return
		}
		serveClaimedFile(w, r, repos, cfg, file)
	}
}
