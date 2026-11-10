package handlers

import (
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"strconv"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/repository"
)

// maxBulkDeleteFiles caps one bulk delete request; the dashboard lists at most
// 100 files, so select-all always fits.
const maxBulkDeleteFiles = 100

type bulkDeleteFailure struct {
	FileID int64  `json:"file_id"`
	Error  string `json:"error"`
}

type bulkDeleteResponse struct {
	RequestedCount int                 `json:"requested_count"`
	DeletedCount   int                 `json:"deleted_count"`
	Deleted        []int64             `json:"deleted"`
	Failed         []bulkDeleteFailure `json:"failed"`
}

func writeBulkDeleteError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// UserBulkDeleteFilesHandler deletes several of the signed-in user's own files
// in one request: POST /api/user/files/delete/bulk {"file_ids": [1, 2, 3]}.
//
// Each file is deleted exactly as the single delete does. A file that isn't
// the user's, no longer exists, or belongs to a bundle (bundles are deleted
// whole, from My Bundles) is reported in "failed" and the rest still go, so
// the response is 200 whenever the request itself is valid.
func UserBulkDeleteFilesHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// JSON only: a cross-site HTML form can send form-encoded or
		// text/plain bodies but not application/json (that needs a CORS
		// preflight), so this backs up the SameSite session cookie.
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			writeBulkDeleteError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var req struct {
			FileIDs []int64 `json:"file_ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBulkDeleteError(w, http.StatusBadRequest, "Invalid request format")
			return
		}

		// Keep the caller's order, drop repeats.
		seen := make(map[int64]bool, len(req.FileIDs))
		ids := make([]int64, 0, len(req.FileIDs))
		for _, id := range req.FileIDs {
			if id <= 0 {
				writeBulkDeleteError(w, http.StatusBadRequest, "Invalid file ID")
				return
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			writeBulkDeleteError(w, http.StatusBadRequest, "No files selected")
			return
		}
		if len(ids) > maxBulkDeleteFiles {
			writeBulkDeleteError(w, http.StatusBadRequest,
				"Too many files: at most "+strconv.Itoa(maxBulkDeleteFiles)+" per request")
			return
		}

		resp := bulkDeleteResponse{
			RequestedCount: len(ids),
			Deleted:        make([]int64, 0, len(ids)),
			Failed:         []bulkDeleteFailure{},
		}
		ctx := r.Context()
		for _, id := range ids {
			file, err := repos.Users.DeleteFile(ctx, id, user.ID)
			if err != nil {
				slog.Warn("user bulk file deletion failed",
					"user_id", user.ID,
					"file_id", id,
					"error", err,
				)
				resp.Failed = append(resp.Failed, bulkDeleteFailure{FileID: id, Error: "File not found or does not belong to you"})
				continue
			}
			if err := finishUserFileDelete(r, cfg, user, file, "user deleted file (bulk)"); err != nil {
				resp.Failed = append(resp.Failed, bulkDeleteFailure{FileID: id, Error: "Internal server error"})
				continue
			}
			resp.Deleted = append(resp.Deleted, id)
		}
		resp.DeletedCount = len(resp.Deleted)

		slog.Info("user bulk file deletion",
			"user_id", user.ID,
			"requested", resp.RequestedCount,
			"deleted", resp.DeletedCount,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
