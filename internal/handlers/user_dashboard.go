package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

// UserDashboardDataHandler returns dashboard data for the logged-in user
func UserDashboardDataHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user from context (set by middleware)
		user := r.Context().Value("user").(*models.User)

		// Parse pagination parameters
		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

		limit := 50 // default
		offset := 0

		if limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
				limit = l
			}
		}

		if offsetStr != "" {
			if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
				offset = o
			}
		}

		// Get user's files
		files, total, err := database.GetFilesByUserID(db, user.ID, limit, offset)
		if err != nil {
			slog.Error("failed to get user files", "error", err, "user_id", user.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Build response with download URLs
		type FileResponse struct {
			ID               int64     `json:"id"`
			ClaimCode        string    `json:"claim_code"`
			OriginalFilename string    `json:"original_filename"`
			FileSize         int64     `json:"file_size"`
			MimeType         string    `json:"mime_type"`
			CreatedAt        time.Time `json:"created_at"`
			ExpiresAt        time.Time `json:"expires_at"`
			MaxDownloads     *int      `json:"max_downloads"`
			DownloadCount    int       `json:"download_count"`
			DownloadURL      string    `json:"download_url"`
			IsExpired        bool      `json:"is_expired"`
			IsPasswordProtected bool   `json:"is_password_protected"`
		}

		fileResponses := make([]FileResponse, 0, len(files))
		for _, file := range files {
			fileResponses = append(fileResponses, FileResponse{
				ID:               file.ID,
				ClaimCode:        file.ClaimCode,
				OriginalFilename: file.OriginalFilename,
				FileSize:         file.FileSize,
				MimeType:         file.MimeType,
				CreatedAt:        file.CreatedAt,
				ExpiresAt:        file.ExpiresAt,
				MaxDownloads:     file.MaxDownloads,
				DownloadCount:    file.DownloadCount,
				DownloadURL:      buildDownloadURL(r, cfg, file.ClaimCode),
				IsExpired:        time.Now().UTC().After(file.ExpiresAt) || (file.MaxDownloads != nil && *file.MaxDownloads > 0 && file.DownloadCount >= *file.MaxDownloads),
				IsPasswordProtected: file.PasswordHash != "",
			})
		}

		response := map[string]interface{}{
			"files":  fileResponses,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// UserDeleteFileHandler allows users to delete their own files
func UserDeleteFileHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user from context
		user := r.Context().Value("user").(*models.User)

		// Parse request
		var req struct {
			FileID int64 `json:"file_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		if req.FileID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid file ID",
			})
			return
		}

		// Delete file (this will fail if file doesn't belong to user)
		file, err := database.DeleteFileByIDAndUserID(db, req.FileID, user.ID)
		if err != nil {
			slog.Warn("user file deletion failed",
				"user_id", user.ID,
				"file_id", req.FileID,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "File not found or does not belong to you",
			})
			return
		}

		// Validate stored filename (defense-in-depth against database corruption/compromise)
		if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
			slog.Error("stored filename validation failed",
				"filename", file.StoredFilename,
				"error", err,
				"user_id", user.ID,
				"client_ip", getClientIP(r),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Internal server error",
			})
			return
		}

		// Delete physical file
		filePath := filepath.Join(cfg.UploadDir, file.StoredFilename)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			slog.Error("failed to delete physical file",
				"path", filePath,
				"error", err,
			)
			// Don't fail the request - database record is already deleted
		}

		// Decrypt if necessary before deletion (for cleanup)
		if utils.IsEncryptionEnabled(cfg.EncryptionKey) {
			slog.Debug("encrypted file deleted", "stored_filename", file.StoredFilename)
		}

		slog.Info("user deleted file",
			"user_id", user.ID,
			"username", user.Username,
			"file_id", file.ID,
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "File deleted successfully",
		})
	}
}
