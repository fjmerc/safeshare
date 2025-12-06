package handlers

import (
	"archive/zip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/fjmerc/safeshare/internal/backup"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/utils"
)

// AdminListBackupsHandler lists available backups
func AdminListBackupsHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get backup directory from config or use default
		backupDir := cfg.BackupDir
		if backupDir == "" {
			backupDir = filepath.Join(cfg.DataDir, "backups")
		}

		// Check if backup directory exists
		if _, err := os.Stat(backupDir); os.IsNotExist(err) {
			// Return empty list if directory doesn't exist
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"backups": []backup.BackupInfo{},
			})
			return
		}

		// List backups
		backups, err := backup.ListBackups(backupDir)
		if err != nil {
			slog.Error("failed to list backups", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to list backups",
			})
			return
		}

		// Transform to frontend-expected format
		backupList := make([]map[string]interface{}, len(backups))
		for i, b := range backups {
			// Check if backup has been verified by looking for .verified marker file
			verifiedMarker := filepath.Join(b.Path, ".verified")
			_, verifiedErr := os.Stat(verifiedMarker)
			isVerified := verifiedErr == nil

			backupList[i] = map[string]interface{}{
				"filename":   b.Name,
				"path":       b.Path,
				"mode":       b.Mode,
				"size":       b.TotalSizeBytes,
				"created_at": b.CreatedAt,
				"version":    b.SafeShareVersion,
				"verified":   isVerified,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"backups": backupList,
		})
	}
}

// AdminCreateBackupHandler creates a new backup
func AdminCreateBackupHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request
		var req struct {
			Mode string `json:"mode"` // config, database, full
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1024) // 1KB limit
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Parse backup mode
		var mode backup.BackupMode
		switch req.Mode {
		case "config":
			mode = backup.ModeConfig
		case "database":
			mode = backup.ModeDatabase
		case "full", "":
			mode = backup.ModeFull
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid backup mode. Must be config, database, or full",
			})
			return
		}

		// Get backup directory from config or use default
		backupDir := cfg.BackupDir
		if backupDir == "" {
			backupDir = filepath.Join(cfg.DataDir, "backups")
		}

		// Ensure backup directory exists
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			slog.Error("failed to create backup directory", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to create backup directory",
			})
			return
		}

		// Create backup options
		opts := backup.CreateOptions{
		Mode:             mode,
		DBPath:           cfg.DBPath,
		UploadsDir:       cfg.UploadDir,
		OutputDir:        backupDir,
		EncryptionKey:    cfg.EncryptionKey,
		SafeShareVersion: cfg.Version,
		}

		// Create backup (synchronous for now)
		slog.Info("starting backup",
			"mode", mode,
			"db", cfg.DBPath,
			"uploads", cfg.UploadDir,
			"output", backupDir,
		)

		result, err := backup.Create(opts)
		if err != nil {
			slog.Error("backup failed", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
			return
		}

		slog.Info("backup completed",
			"path", result.BackupPath,
			"success", result.Success,
			"duration", result.DurationString,
		)

		// Build response with flattened fields for frontend
		response := map[string]interface{}{
			"success":         result.Success,
			"backup_path":     result.BackupPath,
			"filename":        filepath.Base(result.BackupPath),
			"duration_string": result.DurationString,
		}

		if result.Manifest != nil {
			response["mode"] = result.Manifest.Mode
			response["size"] = result.Manifest.Stats.TotalSizeBytes
			response["files_count"] = result.Manifest.Stats.FilesBackedUp
			response["version"] = result.Manifest.SafeShareVersion
			response["created_at"] = result.Manifest.CreatedAt
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// AdminVerifyBackupHandler verifies a backup's integrity
func AdminVerifyBackupHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request - accept either backup_path or filename
		var req struct {
			BackupPath string `json:"backup_path"`
			Filename   string `json:"filename"`
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096) // 4KB limit
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Get backup directory from config
		backupDir := cfg.BackupDir
		if backupDir == "" {
			backupDir = filepath.Join(cfg.DataDir, "backups")
		}

		// Accept either backup_path or filename
		backupPath := req.BackupPath
		if backupPath == "" && req.Filename != "" {
			// If only filename provided, construct full path
			backupPath = filepath.Join(backupDir, req.Filename)
		}

		if backupPath == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "backup_path or filename is required",
			})
			return
		}

		// Security: Ensure backup path is within allowed directory
		absBackupPath, err := filepath.Abs(backupPath)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid backup path",
			})
			return
		}

		absBackupDir, _ := filepath.Abs(backupDir)
		if !isSubPath(absBackupDir, absBackupPath) {
			slog.Warn("attempted path traversal in backup verification",
				"requested", backupPath,
				"allowed", backupDir,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Access denied",
			})
			return
		}

		// Verify backup
		result := backup.Verify(absBackupPath)

		// If verification succeeded, create a .verified marker file
		if result.Valid {
			verifiedMarker := filepath.Join(absBackupPath, ".verified")
			if err := os.WriteFile(verifiedMarker, []byte{}, 0600); err != nil {
				slog.Warn("failed to create verified marker", "path", verifiedMarker, "error", err)
				// Don't fail the verification just because marker creation failed
			} else {
				slog.Info("backup verified and marked", "path", absBackupPath)
			}
		}

		// Build response with frontend-expected fields
		response := map[string]interface{}{
			"valid":  result.Valid,
			"errors": result.Errors,
		}

		if result.Manifest != nil {
			response["mode"] = result.Manifest.Mode
			response["version"] = result.Manifest.SafeShareVersion
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// AdminRestoreBackupHandler restores from a backup
func AdminRestoreBackupHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request - accept either backup_path or filename
		var req struct {
			BackupPath      string `json:"backup_path"`
			Filename        string `json:"filename"`
			HandleOrphans   string `json:"handle_orphans"`   // keep, remove
			OrphanHandling  string `json:"orphan_handling"` // alias for handle_orphans
			DryRun          bool   `json:"dry_run"`
			Force           bool   `json:"force"`
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096) // 4KB limit
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Get backup directory from config
		backupDir := cfg.BackupDir
		if backupDir == "" {
			backupDir = filepath.Join(cfg.DataDir, "backups")
		}

		// Accept either backup_path or filename
		backupPath := req.BackupPath
		if backupPath == "" && req.Filename != "" {
			backupPath = filepath.Join(backupDir, req.Filename)
		}

		if backupPath == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "backup_path or filename is required",
			})
			return
		}

		// Security: Ensure backup path is within allowed directory
		absBackupPath, err := filepath.Abs(backupPath)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid backup path",
			})
			return
		}

		absBackupDir, _ := filepath.Abs(backupDir)
		if !isSubPath(absBackupDir, absBackupPath) {
			slog.Warn("attempted path traversal in backup restore",
				"requested", backupPath,
				"allowed", backupDir,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Access denied",
			})
			return
		}

		// Parse orphan handling (accept either field name)
		orphanHandlingStr := req.HandleOrphans
		if orphanHandlingStr == "" {
			orphanHandlingStr = req.OrphanHandling
		}

		var handleOrphans backup.OrphanHandling
		switch orphanHandlingStr {
		case "remove":
			handleOrphans = backup.OrphanRemove
		case "keep", "":
			handleOrphans = backup.OrphanKeep
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid handle_orphans value. Must be keep or remove",
			})
			return
		}

		// Create restore options
		opts := backup.RestoreOptions{
			InputDir:      absBackupPath,
			DBPath:        cfg.DBPath,
			UploadsDir:    cfg.UploadDir,
			EncryptionKey: cfg.EncryptionKey,
			HandleOrphans: handleOrphans,
			DryRun:        req.DryRun,
			Force:         req.Force,
		}

		// Perform restore
		slog.Info("starting restore",
			"backup", absBackupPath,
			"dry_run", req.DryRun,
			"handle_orphans", handleOrphans,
		)

		result, err := backup.Restore(opts)
		if err != nil {
			slog.Error("restore failed", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
			return
		}

		slog.Info("restore completed",
			"success", result.Success,
			"dry_run", result.DryRun,
			"files_restored", result.FilesRestored,
			"orphans_found", result.OrphansFound,
			"duration", result.DurationString,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

// AdminDeleteBackupHandler deletes a backup
func AdminDeleteBackupHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get backup directory from config
		backupDir := cfg.BackupDir
		if backupDir == "" {
			backupDir = filepath.Join(cfg.DataDir, "backups")
		}

		// Accept filename from query parameter (frontend sends it this way)
		filename := r.URL.Query().Get("filename")
		var backupPath string

		if filename != "" {
			backupPath = filepath.Join(backupDir, filename)
		} else {
			// Fall back to JSON body for backup_path
			var req struct {
				BackupPath string `json:"backup_path"`
			}

			r.Body = http.MaxBytesReader(w, r.Body, 4096) // 4KB limit
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				backupPath = req.BackupPath
			}
		}

		if backupPath == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "filename query parameter or backup_path in body is required",
			})
			return
		}

		// Security: Ensure backup path is within allowed directory
		absBackupPath, err := filepath.Abs(backupPath)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid backup path",
			})
			return
		}

		absBackupDir, _ := filepath.Abs(backupDir)
		if !isSubPath(absBackupDir, absBackupPath) {
			slog.Warn("attempted path traversal in backup deletion",
				"requested", backupPath,
				"allowed", backupDir,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Access denied",
			})
			return
		}

		// Check if path exists and is a directory
		info, err := os.Stat(absBackupPath)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Backup not found",
			})
			return
		}

		if !info.IsDir() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Path is not a backup directory",
			})
			return
		}

		// Delete the backup directory
		if err := os.RemoveAll(absBackupPath); err != nil {
			slog.Error("failed to delete backup", "path", absBackupPath, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Failed to delete backup",
			})
			return
		}

		slog.Info("backup deleted", "path", absBackupPath)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Backup deleted successfully",
		})
	}
}

// AdminDownloadBackupHandler downloads a backup as a zip file
func AdminDownloadBackupHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get backup directory from config
		backupDir := cfg.BackupDir
		if backupDir == "" {
			backupDir = filepath.Join(cfg.DataDir, "backups")
		}

		// Parse request body for filename
		var req struct {
			Filename string `json:"filename"`
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096) // 4KB limit
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		filename := req.Filename
		if filename == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "filename is required",
			})
			return
		}

		backupPath := filepath.Join(backupDir, filename)

		// Security: Ensure backup path is within allowed directory
		absBackupPath, err := filepath.Abs(backupPath)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid backup path",
			})
			return
		}

		absBackupDir, _ := filepath.Abs(backupDir)
		if !isSubPath(absBackupDir, absBackupPath) {
			slog.Warn("attempted path traversal in backup download",
				"requested", backupPath,
				"allowed", backupDir,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Access denied",
			})
			return
		}

		// Check if path exists and is a directory
		info, err := os.Stat(absBackupPath)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Backup not found",
			})
			return
		}

		if !info.IsDir() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Path is not a backup directory",
			})
			return
		}

		// Set headers for zip download
		// Sanitize filename for Content-Disposition header to prevent header injection
		safeFilename := utils.SanitizeForContentDisposition(filename) + ".zip"
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, safeFilename))

		// Create streaming zip writer
		zipWriter := zip.NewWriter(w)
		defer zipWriter.Close()

		slog.Info("starting backup download",
			"backup", filename,
			"path", absBackupPath,
		)

		// Walk the backup directory and add files to zip
		err = filepath.Walk(absBackupPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip the root directory itself
			if path == absBackupPath {
				return nil
			}

			// Security: Skip symlinks to prevent path traversal attacks
			if info.Mode()&os.ModeSymlink != 0 {
				slog.Warn("skipping symlink in backup download", "path", path)
				return nil
			}

			// Security: Verify file is actually within backup directory
			// This protects against symlinks that might have been followed
			realPath, evalErr := filepath.EvalSymlinks(path)
			if evalErr != nil {
				slog.Warn("cannot resolve path in backup download", "path", path, "error", evalErr)
				return nil
			}
			if !isSubPath(absBackupPath, realPath) && realPath != absBackupPath {
				slog.Warn("path escapes backup directory", "path", path, "realPath", realPath)
				return nil
			}

			// Get relative path for zip entry
			relPath, err := filepath.Rel(absBackupPath, path)
			if err != nil {
				return err
			}

			// Create zip header
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = relPath

			if info.IsDir() {
				header.Name += "/"
				_, err = zipWriter.CreateHeader(header)
				return err
			}

			// Use deflate compression for files
			header.Method = zip.Deflate

			// Create file entry in zip
			writer, err := zipWriter.CreateHeader(header)
			if err != nil {
				return err
			}

			// Open and copy file content
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(writer, file)
			return err
		})

		if err != nil {
			slog.Error("failed to create backup zip", "error", err)
			// Can't change headers after we've started writing, so just log the error
			return
		}

		slog.Info("backup download completed", "backup", filename)
	}
}

// isSubPath checks if child is a subdirectory of parent
func isSubPath(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)

	// Check if child starts with parent
	if len(child) <= len(parent) {
		return false
	}

	// Ensure proper path prefix matching
	return child[:len(parent)] == parent && child[len(parent)] == filepath.Separator
}
