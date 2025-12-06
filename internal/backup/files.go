package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// PartialUploadDir is the directory containing partial uploads (excluded from backup)
	PartialUploadDir = ".partial"
)

// CopyUploadsDir copies all files from source uploads directory to destination
// Excludes the .partial directory which contains temporary chunked uploads
func CopyUploadsDir(srcDir, destDir string, progressCallback func(current, total int, filename string)) (int, int64, error) {
	// Ensure source directory exists
	srcInfo, err := os.Stat(srcDir)
	if err != nil {
		return 0, 0, fmt.Errorf("source directory not accessible: %w", err)
	}
	if !srcInfo.IsDir() {
		return 0, 0, fmt.Errorf("source path is not a directory: %s", srcDir)
	}

	// Create destination directory with secure permissions
	if err := os.MkdirAll(destDir, BackupDirPerms); err != nil {
		return 0, 0, fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Get list of files to copy (excluding .partial)
	files, err := getFilesToBackup(srcDir)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to list files: %w", err)
	}

	var totalSize int64
	copied := 0

	for i, file := range files {
		srcPath := filepath.Join(srcDir, file)
		destPath := filepath.Join(destDir, file)

		if progressCallback != nil {
			progressCallback(i+1, len(files), file)
		}

		// Copy file
		size, err := copyFileWithSize(srcPath, destPath)
		if err != nil {
			return copied, totalSize, fmt.Errorf("failed to copy %s: %w", file, err)
		}

		copied++
		totalSize += size
	}

	return copied, totalSize, nil
}

// RestoreUploadsDir restores files from backup to uploads directory
func RestoreUploadsDir(backupDir, destDir string, progressCallback func(current, total int, filename string)) (int, error) {
	// Ensure backup directory exists
	if _, err := os.Stat(backupDir); err != nil {
		return 0, fmt.Errorf("backup directory not accessible")
	}

	// Get absolute path of destination for path traversal protection
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		return 0, fmt.Errorf("invalid destination directory")
	}

	// Create destination directory with secure permissions
	if err := os.MkdirAll(destDir, BackupDirPerms); err != nil {
		return 0, fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Get list of files to restore
	files, err := listFiles(backupDir)
	if err != nil {
		return 0, fmt.Errorf("failed to list backup files: %w", err)
	}

	restored := 0

	for i, file := range files {
		// Security: Validate filename to prevent path traversal
		if err := validateFilename(file); err != nil {
			return restored, fmt.Errorf("invalid filename in backup: %s", file)
		}

		srcPath := filepath.Join(backupDir, file)
		destPath := filepath.Join(destDir, file)

		// Security: Verify destination is within destDir (defense in depth)
		absDestPath, err := filepath.Abs(destPath)
		if err != nil || !strings.HasPrefix(absDestPath, absDestDir+string(filepath.Separator)) {
			return restored, fmt.Errorf("path traversal detected: %s", file)
		}

		if progressCallback != nil {
			progressCallback(i+1, len(files), file)
		}

		// Copy file
		if _, err := copyFileWithSize(srcPath, destPath); err != nil {
			return restored, fmt.Errorf("failed to restore %s: %w", file, err)
		}

		restored++
	}

	return restored, nil
}

// validateFilename checks that a filename is safe (no path components)
func validateFilename(filename string) error {
	// Reject empty filenames
	if filename == "" {
		return fmt.Errorf("empty filename")
	}

	// Reject filenames with path separators
	if strings.ContainsAny(filename, `/\`) {
		return fmt.Errorf("filename contains path separator")
	}

	// Reject path traversal sequences
	if filename == ".." || strings.HasPrefix(filename, "../") || strings.HasPrefix(filename, "..\\" ) {
		return fmt.Errorf("filename contains path traversal")
	}

	// Reject filenames starting with . (hidden files, could be .partial, etc.)
	if strings.HasPrefix(filename, ".") {
		return fmt.Errorf("filename starts with dot")
	}

	return nil
}

// getFilesToBackup returns a list of files to backup from uploads directory
// Excludes .partial directory and any hidden files/directories
func getFilesToBackup(uploadsDir string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(uploadsDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		name := entry.Name()

		// Skip .partial directory
		if name == PartialUploadDir {
			continue
		}

		// Skip hidden files/directories (starting with .)
		if strings.HasPrefix(name, ".") {
			continue
		}

		// Skip directories (we only backup files in uploads, no subdirectories except .partial)
		if entry.IsDir() {
			continue
		}

		files = append(files, name)
	}

	return files, nil
}

// listFiles returns a list of all files in a directory (non-recursive)
func listFiles(dir string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}

	return files, nil
}

// copyFileWithSize copies a file and returns the number of bytes copied
func copyFileWithSize(src, dst string) (int64, error) {
	sourceFile, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer sourceFile.Close()

	// Get source file info for permissions
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return 0, err
	}

	destFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, sourceInfo.Mode())
	if err != nil {
		return 0, err
	}
	defer destFile.Close()

	written, err := io.Copy(destFile, sourceFile)
	if err != nil {
		return written, err
	}

	// Sync to ensure data is written to disk
	if err := destFile.Sync(); err != nil {
		return written, err
	}

	return written, nil
}

// CountUploadFiles counts the number of files in uploads directory (excluding .partial)
func CountUploadFiles(uploadsDir string) (int, error) {
	files, err := getFilesToBackup(uploadsDir)
	if err != nil {
		return 0, err
	}
	return len(files), nil
}

// GetUploadsTotalSize calculates total size of files in uploads directory (excluding .partial)
func GetUploadsTotalSize(uploadsDir string) (int64, error) {
	files, err := getFilesToBackup(uploadsDir)
	if err != nil {
		return 0, err
	}

	var totalSize int64
	for _, file := range files {
		info, err := os.Stat(filepath.Join(uploadsDir, file))
		if err != nil {
			return 0, err
		}
		totalSize += info.Size()
	}

	return totalSize, nil
}

// FindOrphanedFiles identifies files in uploads that don't have database records
func FindOrphanedFiles(uploadsDir string, dbStoredFilenames map[string]bool) ([]string, error) {
	files, err := getFilesToBackup(uploadsDir)
	if err != nil {
		return nil, err
	}

	var orphans []string
	for _, file := range files {
		if !dbStoredFilenames[file] {
			orphans = append(orphans, file)
		}
	}

	return orphans, nil
}

// FindMissingFiles identifies database records that don't have corresponding files
func FindMissingFiles(uploadsDir string, dbRecords []FileRecord) ([]FileRecord, error) {
	// Get set of existing files
	files, err := getFilesToBackup(uploadsDir)
	if err != nil {
		return nil, err
	}

	existingFiles := make(map[string]bool)
	for _, file := range files {
		existingFiles[file] = true
	}

	// Find records without files
	var missing []FileRecord
	for _, record := range dbRecords {
		if !existingFiles[record.StoredFilename] {
			missing = append(missing, record)
		}
	}

	return missing, nil
}

// VerifyUploadsIntegrity checks that all expected files exist in uploads directory
func VerifyUploadsIntegrity(uploadsDir string, expectedFiles []string) ([]string, error) {
	var missing []string

	for _, file := range expectedFiles {
		filePath := filepath.Join(uploadsDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			missing = append(missing, file)
		} else if err != nil {
			return nil, fmt.Errorf("error checking file %s: %w", file, err)
		}
	}

	return missing, nil
}

// CleanupUploadsDir removes files from uploads directory that are not in the whitelist
// This is used during restore to remove files that were uploaded after the backup
func CleanupUploadsDir(uploadsDir string, keepFiles map[string]bool) (int, error) {
	files, err := getFilesToBackup(uploadsDir)
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, file := range files {
		if !keepFiles[file] {
			filePath := filepath.Join(uploadsDir, file)
			if err := os.Remove(filePath); err != nil {
				return removed, fmt.Errorf("failed to remove %s: %w", file, err)
			}
			removed++
		}
	}

	return removed, nil
}
