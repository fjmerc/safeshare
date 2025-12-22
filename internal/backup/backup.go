package backup

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

// Create creates a backup according to the specified options
func Create(opts CreateOptions) (*BackupResult, error) {
	startTime := time.Now()
	result := &BackupResult{}

	// Validate options
	if err := validateCreateOptions(&opts); err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, err
	}

	// Generate backup directory name
	backupDirName := GetBackupDirName()
	backupPath := filepath.Join(opts.OutputDir, backupDirName)

	// Create backup directory atomically (fails if exists, preventing TOCTOU race)
	if err := os.Mkdir(backupPath, BackupDirPerms); err != nil {
		if os.IsExist(err) {
			// Generate unique suffix and retry
			backupDirName = fmt.Sprintf("%s-%d", backupDirName, time.Now().UnixNano())
			backupPath = filepath.Join(opts.OutputDir, backupDirName)
			if err := os.Mkdir(backupPath, BackupDirPerms); err != nil {
				result.Error = fmt.Sprintf("failed to create backup directory: %v", err)
				result.Duration = time.Since(startTime)
				result.DurationString = result.Duration.String()
				return result, fmt.Errorf("failed to create backup directory: %w", err)
			}
		} else {
			result.Error = fmt.Sprintf("failed to create backup directory: %v", err)
			result.Duration = time.Since(startTime)
			result.DurationString = result.Duration.String()
			return result, fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// Verify it's a directory and not a symlink (defense against symlink attacks)
	info, err := os.Lstat(backupPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		os.Remove(backupPath)
		result.Error = "backup path is not a regular directory"
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, fmt.Errorf("%s", result.Error)
	}

	// Create manifest
	manifest := NewManifest(opts.Mode, opts.SafeShareVersion)
	manifest.SourceDBPath = opts.DBPath
	manifest.SourceUploadsDir = opts.UploadsDir

	// Set encryption info
	if opts.EncryptionKey != "" {
		manifest.Encryption.Enabled = true
		manifest.Encryption.KeyFingerprint = ComputeKeyFingerprint(opts.EncryptionKey)
	}

	// Progress tracking
	totalSteps := calculateTotalSteps(opts.Mode, opts.UploadsDir)
	currentStep := 0

	reportProgress := func(description string) {
		currentStep++
		if opts.ProgressCallback != nil {
			opts.ProgressCallback(currentStep, totalSteps, description)
		}
	}

	// Step 1: Backup database
	reportProgress("Backing up database...")
	dbBackupPath := filepath.Join(backupPath, DatabaseFilename)

	var dbErr error
	switch opts.Mode {
	case ModeConfig:
		dbErr = backupConfigOnly(opts.DBPath, dbBackupPath)
	case ModeDatabase, ModeFull:
		dbErr = BackupDatabase(opts.DBPath, dbBackupPath)
	}

	if dbErr != nil {
		// Clean up on failure
		os.RemoveAll(backupPath)
		result.Error = fmt.Sprintf("failed to backup database: %v", dbErr)
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, fmt.Errorf("failed to backup database: %w", dbErr)
	}

	// Step 2: Compute database checksum
	reportProgress("Computing database checksum...")
	dbChecksum, err := ComputeChecksum(dbBackupPath)
	if err != nil {
		os.RemoveAll(backupPath)
		result.Error = fmt.Sprintf("failed to compute database checksum: %v", err)
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, fmt.Errorf("failed to compute database checksum: %w", err)
	}
	manifest.Checksums[DatabaseFilename] = dbChecksum

	// Get database size
	dbSize, _ := GetFileSize(dbBackupPath)
	manifest.Stats.DatabaseSizeBytes = dbSize

	// Step 3: Get database stats
	reportProgress("Gathering database statistics...")
	stats, err := GetDatabaseStats(dbBackupPath)
	if err != nil {
		// Non-fatal, continue with empty stats
		manifest.Warnings = append(manifest.Warnings, fmt.Sprintf("Could not gather database stats: %v", err))
	} else {
		manifest.Stats.UsersCount = stats.UsersCount
		manifest.Stats.FileRecordsCount = stats.FileRecordsCount
		manifest.Stats.WebhooksCount = stats.WebhooksCount
		manifest.Stats.APITokensCount = stats.APITokensCount
		manifest.Stats.BlockedIPsCount = stats.BlockedIPsCount
	}

	// Step 4: Copy uploads (full mode only)
	if opts.Mode == ModeFull {
		reportProgress("Copying uploaded files...")
		uploadsBackupPath := filepath.Join(backupPath, UploadsDirname)

		filesCopied, filesSize, err := CopyUploadsDir(opts.UploadsDir, uploadsBackupPath, func(current, total int, filename string) {
			if opts.ProgressCallback != nil {
				opts.ProgressCallback(currentStep, totalSteps, fmt.Sprintf("Copying file %d/%d: %s", current, total, filename))
			}
		})

		if err != nil {
			os.RemoveAll(backupPath)
			result.Error = fmt.Sprintf("failed to copy uploads: %v", err)
			result.Duration = time.Since(startTime)
			result.DurationString = result.Duration.String()
			return result, fmt.Errorf("failed to copy uploads: %w", err)
		}

		manifest.Stats.FilesBackedUp = filesCopied
		manifest.Stats.FilesSizeBytes = filesSize

		// Compute checksums for all uploaded files
		reportProgress("Computing file checksums...")
		files, _ := listFiles(uploadsBackupPath)
		for _, file := range files {
			filePath := filepath.Join(uploadsBackupPath, file)
			checksum, err := ComputeChecksum(filePath)
			if err != nil {
				manifest.Warnings = append(manifest.Warnings, fmt.Sprintf("Could not compute checksum for %s: %v", file, err))
				continue
			}
			manifest.Checksums[filepath.Join(UploadsDirname, file)] = checksum
		}
	} else {
		// Add warning for non-full backups
		if manifest.Stats.FileRecordsCount > 0 {
			manifest.Warnings = append(manifest.Warnings,
				fmt.Sprintf("Files not included - %d file metadata records preserved but files not recoverable", manifest.Stats.FileRecordsCount))
		}
	}

	// Calculate total size
	manifest.Stats.TotalSizeBytes = manifest.Stats.DatabaseSizeBytes + manifest.Stats.FilesSizeBytes

	// Step 5: Write manifest
	reportProgress("Writing manifest...")
	if err := WriteManifest(manifest, backupPath); err != nil {
		os.RemoveAll(backupPath)
		result.Error = fmt.Sprintf("failed to write manifest: %v", err)
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, fmt.Errorf("failed to write manifest: %w", err)
	}

	// Success
	result.Success = true
	result.BackupPath = backupPath
	result.Manifest = manifest
	result.Duration = time.Since(startTime)
	result.DurationString = result.Duration.String()

	return result, nil
}

// validateCreateOptions validates backup creation options
func validateCreateOptions(opts *CreateOptions) error {
	if !opts.Mode.IsValid() {
		return fmt.Errorf("invalid backup mode: %s", opts.Mode)
	}

	if opts.DBPath == "" {
		return fmt.Errorf("database path is required")
	}

	if _, err := os.Stat(opts.DBPath); err != nil {
		return fmt.Errorf("database not accessible: %w", err)
	}

	if opts.OutputDir == "" {
		return fmt.Errorf("output directory is required")
	}

	// For full mode, uploads directory is required
	if opts.Mode == ModeFull {
		if opts.UploadsDir == "" {
			return fmt.Errorf("uploads directory is required for full backup mode")
		}
		if _, err := os.Stat(opts.UploadsDir); err != nil {
			return fmt.Errorf("uploads directory not accessible: %w", err)
		}
	}

	return nil
}

// calculateTotalSteps estimates total steps for progress reporting
func calculateTotalSteps(mode BackupMode, uploadsDir string) int {
	// Base steps: backup db, compute checksum, get stats, write manifest
	steps := 4

	if mode == ModeFull {
		// Add: copy uploads, compute file checksums
		steps += 2
	}

	return steps
}

// backupConfigOnly creates a database backup containing only configuration tables
func backupConfigOnly(sourcePath, destPath string) error {
	// First, create a full backup
	if err := BackupDatabase(sourcePath, destPath); err != nil {
		return fmt.Errorf("failed to create initial backup: %w", err)
	}

	// Then, delete non-config tables from the backup
	db, err := sql.Open("sqlite", destPath)
	if err != nil {
		os.Remove(destPath)
		return fmt.Errorf("failed to open backup database: %w", err)
	}
	defer db.Close()

	// Tables to keep for config-only backup
	keepTables := map[string]bool{
		"settings":          true,
		"admin_credentials": true,
		"blocked_ips":       true,
		"webhook_configs":   true,
	}

	// Get all user tables
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		os.Remove(destPath)
		return fmt.Errorf("failed to query tables: %w", err)
	}

	var tablesToDelete []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			os.Remove(destPath)
			return fmt.Errorf("failed to scan table name: %w", err)
		}
		if !keepTables[name] {
			tablesToDelete = append(tablesToDelete, name)
		}
	}
	rows.Close()

	// Delete non-config tables
	for _, table := range tablesToDelete {
		_, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS \"%s\"", table))
		if err != nil {
			os.Remove(destPath)
			return fmt.Errorf("failed to drop table %s: %w", table, err)
		}
	}

	// Vacuum to reclaim space
	_, err = db.Exec("VACUUM")
	if err != nil {
		// Non-fatal warning
		fmt.Printf("Warning: VACUUM failed: %v\n", err)
	}

	return nil
}

// ListBackups returns information about all backups in a directory
func ListBackups(backupsDir string) ([]BackupInfo, error) {
	var backups []BackupInfo

	entries, err := os.ReadDir(backupsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return backups, nil // Empty list if directory doesn't exist
		}
		return nil, fmt.Errorf("failed to read backups directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		backupPath := filepath.Join(backupsDir, entry.Name())
		manifestPath := filepath.Join(backupPath, ManifestFilename)

		// Check if manifest exists
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			continue // Not a valid backup directory
		}

		// Read manifest
		manifest, err := ReadManifest(backupPath)
		if err != nil {
			continue // Skip invalid backups
		}

		// Get total size
		totalSize, _ := GetDirectorySize(backupPath)

		backups = append(backups, BackupInfo{
			Path:             backupPath,
			Name:             entry.Name(),
			CreatedAt:        manifest.CreatedAt,
			Mode:             manifest.Mode,
			SafeShareVersion: manifest.SafeShareVersion,
			TotalSizeBytes:   totalSize,
			FileRecordsCount: manifest.Stats.FileRecordsCount,
			FilesBackedUp:    manifest.Stats.FilesBackedUp,
		})
	}

	// Sort by CreatedAt descending (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	return backups, nil
}
