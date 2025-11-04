package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/yourusername/safeshare/internal/models"
)

// CreateFile inserts a new file record into the database
func CreateFile(db *sql.DB, file *models.File) error {
	query := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, max_downloads, uploader_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := db.Exec(
		query,
		file.ClaimCode,
		file.OriginalFilename,
		file.StoredFilename,
		file.FileSize,
		file.MimeType,
		file.ExpiresAt,
		file.MaxDownloads,
		file.UploaderIP,
	)
	if err != nil {
		return fmt.Errorf("failed to insert file: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	file.ID = id
	return nil
}

// GetFileByClaimCode retrieves a file record by its claim code
// Returns nil if not found or expired
func GetFileByClaimCode(db *sql.DB, claimCode string) (*models.File, error) {
	query := `
		SELECT
			id, claim_code, original_filename, stored_filename, file_size,
			mime_type, created_at, expires_at, max_downloads, download_count, uploader_ip
		FROM files
		WHERE claim_code = ?
	`

	file := &models.File{}
	var createdAt, expiresAt string

	err := db.QueryRow(query, claimCode).Scan(
		&file.ID,
		&file.ClaimCode,
		&file.OriginalFilename,
		&file.StoredFilename,
		&file.FileSize,
		&file.MimeType,
		&createdAt,
		&expiresAt,
		&file.MaxDownloads,
		&file.DownloadCount,
		&file.UploaderIP,
	)

	if err == sql.ErrNoRows {
		return nil, nil // File not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query file: %w", err)
	}

	// Parse timestamps (SQLite returns RFC3339 format)
	file.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	file.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	// Check if expired
	if time.Now().After(file.ExpiresAt) {
		return nil, nil // Expired file treated as not found
	}

	return file, nil
}

// IncrementDownloadCount atomically increments the download counter for a file
func IncrementDownloadCount(db *sql.DB, id int64) error {
	query := `UPDATE files SET download_count = download_count + 1 WHERE id = ?`

	result, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to increment download count: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("no file found with id %d", id)
	}

	return nil
}

// DeleteExpiredFiles removes expired files from both database and filesystem
// Returns the count of deleted files
func DeleteExpiredFiles(db *sql.DB, uploadDir string) (int, error) {
	// Find expired files
	query := `
		SELECT id, stored_filename
		FROM files
		WHERE expires_at <= datetime('now')
	`

	rows, err := db.Query(query)
	if err != nil {
		return 0, fmt.Errorf("failed to query expired files: %w", err)
	}
	defer rows.Close()

	var expiredFiles []struct {
		ID             int64
		StoredFilename string
	}

	for rows.Next() {
		var f struct {
			ID             int64
			StoredFilename string
		}
		if err := rows.Scan(&f.ID, &f.StoredFilename); err != nil {
			slog.Error("failed to scan expired file", "error", err)
			continue
		}
		expiredFiles = append(expiredFiles, f)
	}

	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("error iterating expired files: %w", err)
	}

	// Delete files
	deletedCount := 0
	for _, f := range expiredFiles {
		// Delete from database first
		deleteQuery := `DELETE FROM files WHERE id = ?`
		if _, err := db.Exec(deleteQuery, f.ID); err != nil {
			slog.Error("failed to delete file record", "id", f.ID, "error", err)
			continue
		}

		// Delete physical file
		filePath := filepath.Join(uploadDir, f.StoredFilename)
		if err := os.Remove(filePath); err != nil {
			if !os.IsNotExist(err) {
				slog.Error("failed to delete physical file", "path", filePath, "error", err)
			}
			// Continue even if physical file deletion fails
		}

		deletedCount++
	}

	return deletedCount, nil
}

// GetStats returns statistics about the file storage
func GetStats(db *sql.DB, uploadDir string) (totalFiles int, storageUsed int64, err error) {
	// Count active files (not expired)
	query := `
		SELECT COUNT(*), COALESCE(SUM(file_size), 0)
		FROM files
		WHERE expires_at > datetime('now')
	`

	err = db.QueryRow(query).Scan(&totalFiles, &storageUsed)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get stats: %w", err)
	}

	return totalFiles, storageUsed, nil
}
