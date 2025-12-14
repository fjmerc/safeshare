package backup

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	_ "modernc.org/sqlite"
)

const (
	// BackupDirPerms is the permission mode for backup directories (owner only)
	BackupDirPerms = 0700
	// BackupFilePerms is the permission mode for backup files (owner only)
	BackupFilePerms = 0600
)

// validPathPattern matches safe path characters (no SQL injection chars)
var validPathPattern = regexp.MustCompile(`^[a-zA-Z0-9/_.-]+$`)

// validatePathForSQL ensures a path is safe for use in SQL literals
// This prevents SQL injection in commands like VACUUM INTO that don't support parameters
func validatePathForSQL(path string) error {
	// Path must be absolute
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute")
	}

	// Reject paths containing SQL injection characters
	if !validPathPattern.MatchString(path) {
		return fmt.Errorf("path contains invalid characters")
	}

	return nil
}

// BackupDatabase creates a hot backup of a SQLite database
// This uses VACUUM INTO which creates a consistent snapshot and handles WAL mode correctly
func BackupDatabase(sourcePath, destPath string) error {
	// Convert to absolute path and validate for SQL safety
	absDestPath, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}

	// Validate path is safe for SQL (prevents SQL injection)
	if err := validatePathForSQL(absDestPath); err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}

	// Ensure destination directory exists
	destDir := filepath.Dir(absDestPath)
	if err := os.MkdirAll(destDir, BackupDirPerms); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Remove destination if it exists (VACUUM INTO fails if file exists)
	if err := os.Remove(absDestPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing destination: %w", err)
	}

	// Open source database
	db, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		return fmt.Errorf("failed to open source database: %w", err)
	}
	defer db.Close()

	// Verify source database is accessible
	if err := db.Ping(); err != nil {
		return fmt.Errorf("source database is not accessible: %w", err)
	}

	// Use VACUUM INTO to create a consistent backup
	// This is atomic and works correctly with WAL mode
	// Path is validated above to prevent SQL injection
	_, err = db.Exec(fmt.Sprintf("VACUUM INTO '%s'", absDestPath))
	if err != nil {
		return fmt.Errorf("failed to backup database: %w", err)
	}

	// Set secure file permissions
	if err := os.Chmod(absDestPath, BackupFilePerms); err != nil {
		// Non-fatal, log warning but continue
	}

	// Verify the backup was created
	if _, err := os.Stat(absDestPath); err != nil {
		return fmt.Errorf("backup file was not created: %w", err)
	}

	return nil
}

// RestoreDatabase restores a database from a backup file
// The destination database file will be replaced
func RestoreDatabase(backupPath, destPath string) error {
	// Verify backup file exists
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file not found")
	}

	// Ensure destination directory exists
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, BackupDirPerms); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// If destination exists, remove it and any WAL/SHM files
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := destPath + suffix
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing file %s: %w", path, err)
		}
	}

	// Copy backup file to destination
	if err := copyFile(backupPath, destPath); err != nil {
		return fmt.Errorf("failed to copy database: %w", err)
	}

	// Verify the restored database
	if err := ValidateDatabase(destPath); err != nil {
		// Clean up the invalid restore
		os.Remove(destPath)
		return fmt.Errorf("restored database is invalid: %w", err)
	}

	return nil
}

// ValidateDatabase checks if a SQLite database is valid and accessible
func ValidateDatabase(dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Ping the database
	if err := db.Ping(); err != nil {
		return fmt.Errorf("database is not accessible: %w", err)
	}

	// Run integrity check
	var result string
	err = db.QueryRow("PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}

	if result != "ok" {
		return fmt.Errorf("database integrity check failed: %s", result)
	}

	return nil
}

// GetTableCounts returns counts for all tables in the database
func GetTableCounts(db *sql.DB) (map[string]int, error) {
	counts := make(map[string]int)

	// Get list of tables
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, name)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating tables: %w", err)
	}

	// Get count for each table
	for _, table := range tables {
		var count int
		// Use fmt.Sprintf since table names can't be parameterized
		// Table names come from sqlite_master, so they're safe
		err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM \"%s\"", table)).Scan(&count)
		if err != nil {
			return nil, fmt.Errorf("failed to count rows in %s: %w", table, err)
		}
		counts[table] = count
	}

	return counts, nil
}

// GetDatabaseStats retrieves statistics from the database for backup manifest
func GetDatabaseStats(dbPath string) (*BackupStats, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	stats := &BackupStats{}

	// Count users
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&stats.UsersCount)
	if err != nil && !isTableNotFound(err) {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}

	// Count file records
	err = db.QueryRow("SELECT COUNT(*) FROM files").Scan(&stats.FileRecordsCount)
	if err != nil && !isTableNotFound(err) {
		return nil, fmt.Errorf("failed to count files: %w", err)
	}

	// Count webhooks
	err = db.QueryRow("SELECT COUNT(*) FROM webhook_configs").Scan(&stats.WebhooksCount)
	if err != nil && !isTableNotFound(err) {
		// Table might not exist in older versions
		stats.WebhooksCount = 0
	}

	// Count API tokens
	err = db.QueryRow("SELECT COUNT(*) FROM api_tokens").Scan(&stats.APITokensCount)
	if err != nil && !isTableNotFound(err) {
		// Table might not exist in older versions
		stats.APITokensCount = 0
	}

	// Count blocked IPs
	err = db.QueryRow("SELECT COUNT(*) FROM blocked_ips").Scan(&stats.BlockedIPsCount)
	if err != nil && !isTableNotFound(err) {
		// Table might not exist in older versions
		stats.BlockedIPsCount = 0
	}

	return stats, nil
}

// GetFileRecords retrieves all file records from the database
func GetFileRecords(dbPath string) ([]FileRecord, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT claim_code, original_filename, stored_filename, file_size FROM files")
	if err != nil {
		return nil, fmt.Errorf("failed to query files: %w", err)
	}
	defer rows.Close()

	var records []FileRecord
	for rows.Next() {
		var r FileRecord
		if err := rows.Scan(&r.ClaimCode, &r.OriginalFilename, &r.StoredFilename, &r.FileSize); err != nil {
			return nil, fmt.Errorf("failed to scan file record: %w", err)
		}
		records = append(records, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating file records: %w", err)
	}

	return records, nil
}

// FileRecord represents a file entry from the database (minimal fields for backup)
type FileRecord struct {
	ClaimCode        string
	OriginalFilename string
	StoredFilename   string
	FileSize         int64
}

// DeleteOrphanedFileRecords removes file records that don't have corresponding files
func DeleteOrphanedFileRecords(dbPath string, storedFilenames []string) (int, error) {
	if len(storedFilenames) == 0 {
		return 0, nil
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Build placeholders for IN clause
	placeholders := ""
	args := make([]interface{}, len(storedFilenames))
	for i, filename := range storedFilenames {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args[i] = filename
	}

	// Delete orphaned records
	result, err := db.Exec(
		fmt.Sprintf("DELETE FROM files WHERE stored_filename IN (%s)", placeholders),
		args...,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to delete orphaned records: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows: %w", err)
	}

	return int(count), nil
}

// isTableNotFound checks if an error indicates a missing table
func isTableNotFound(err error) bool {
	if err == nil {
		return false
	}
	// Check for common "no such table" error patterns
	errStr := err.Error()
	return contains(errStr, "no such table") || contains(errStr, "doesn't exist")
}

// contains checks if s contains substr (case-sensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

// containsAt is a helper for contains
func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	// Sync to ensure data is written to disk
	return destFile.Sync()
}
