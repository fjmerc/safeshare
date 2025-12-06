package backup

import (
	"crypto/subtle"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Restore restores from a backup according to the specified options
func Restore(opts RestoreOptions) (*RestoreResult, error) {
	startTime := time.Now()
	result := &RestoreResult{
		Warnings: []string{},
	}

	// Validate options
	if err := validateRestoreOptions(&opts); err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, err
	}

	// Read and validate manifest
	manifest, err := ReadManifest(opts.InputDir)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read manifest: %v", err)
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, fmt.Errorf("failed to read manifest: %w", err)
	}

	if err := ValidateManifest(manifest); err != nil {
		result.Error = fmt.Sprintf("invalid manifest: %v", err)
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, fmt.Errorf("invalid manifest: %w", err)
	}

	// Verify encryption key fingerprint if encryption was enabled
	// Use constant-time comparison to prevent timing attacks
	if manifest.Encryption.Enabled && opts.EncryptionKey != "" {
		expectedFingerprint := manifest.Encryption.KeyFingerprint
		actualFingerprint := ComputeKeyFingerprint(opts.EncryptionKey)
		if subtle.ConstantTimeCompare([]byte(expectedFingerprint), []byte(actualFingerprint)) != 1 {
			result.Warnings = append(result.Warnings,
				"Encryption key fingerprint does not match backup - files may not be decryptable")
		}
	}

	// Progress tracking
	totalSteps := calculateRestoreSteps(manifest)
	currentStep := 0

	reportProgress := func(description string) {
		currentStep++
		if opts.ProgressCallback != nil {
			opts.ProgressCallback(currentStep, totalSteps, description)
		}
	}

	// Dry run mode
	result.DryRun = opts.DryRun
	if opts.DryRun {
		return performDryRun(opts, manifest, result, reportProgress)
	}

	// Step 1: Verify backup integrity
	reportProgress("Verifying backup integrity...")
	verifyResult := Verify(opts.InputDir)
	if !verifyResult.Valid {
		result.Error = fmt.Sprintf("backup integrity check failed: %v", verifyResult.Errors)
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, fmt.Errorf("backup integrity check failed: %v", verifyResult.Errors)
	}

	// Step 2: Check for existing data
	if !opts.Force {
		if _, err := os.Stat(opts.DBPath); err == nil {
			result.Error = "destination database already exists (use --force to overwrite)"
			result.Duration = time.Since(startTime)
			result.DurationString = result.Duration.String()
			return result, fmt.Errorf("%s", result.Error)
		}
	}

	// Step 3: Restore database
	reportProgress("Restoring database...")
	dbBackupPath := filepath.Join(opts.InputDir, DatabaseFilename)
	if err := RestoreDatabase(dbBackupPath, opts.DBPath); err != nil {
		result.Error = fmt.Sprintf("failed to restore database: %v", err)
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, fmt.Errorf("failed to restore database: %w", err)
	}

	// Track restored tables
	result.TablesRestored = getRestoredTables(manifest)

	// Step 4: Handle file restoration and orphans
	if manifest.Includes.Files && manifest.Stats.FilesBackedUp > 0 {
		// Full backup - restore files
		reportProgress("Restoring uploaded files...")
		uploadsBackupPath := filepath.Join(opts.InputDir, UploadsDirname)

		filesRestored, err := RestoreUploadsDir(uploadsBackupPath, opts.UploadsDir, func(current, total int, filename string) {
			if opts.ProgressCallback != nil {
				opts.ProgressCallback(currentStep, totalSteps, fmt.Sprintf("Restoring file %d/%d: %s", current, total, filename))
			}
		})

		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("File restoration error: %v", err))
		}
		result.FilesRestored = filesRestored
	} else if manifest.Includes.FileMetadata && manifest.Stats.FileRecordsCount > 0 {
		// Database-only backup - handle orphans
		reportProgress("Checking for orphaned file records...")
		orphanResult, err := handleOrphans(opts, manifest)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Orphan handling error: %v", err))
		} else {
			result.OrphansFound = orphanResult.found
			result.OrphansRemoved = orphanResult.removed
			result.OrphansKept = orphanResult.kept
		}
	}

	// Success
	result.Success = true
	result.Duration = time.Since(startTime)
	result.DurationString = result.Duration.String()

	return result, nil
}

// validateRestoreOptions validates restore options
func validateRestoreOptions(opts *RestoreOptions) error {
	if opts.InputDir == "" {
		return fmt.Errorf("input directory is required")
	}

	if _, err := os.Stat(opts.InputDir); err != nil {
		return fmt.Errorf("input directory not accessible: %w", err)
	}

	if opts.DBPath == "" {
		return fmt.Errorf("database path is required")
	}

	if !opts.HandleOrphans.IsValid() {
		return fmt.Errorf("invalid orphan handling mode: %s", opts.HandleOrphans)
	}

	// Prompt mode requires callback
	if opts.HandleOrphans == OrphanPrompt && opts.OrphanCallback == nil {
		return fmt.Errorf("orphan callback is required for prompt mode")
	}

	return nil
}

// calculateRestoreSteps estimates total steps for progress reporting
func calculateRestoreSteps(manifest *BackupManifest) int {
	// Base steps: verify, check existing, restore db
	steps := 3

	if manifest.Includes.Files && manifest.Stats.FilesBackedUp > 0 {
		steps++ // Restore files
	} else if manifest.Includes.FileMetadata && manifest.Stats.FileRecordsCount > 0 {
		steps++ // Handle orphans
	}

	return steps
}

// getRestoredTables returns list of tables that were restored based on backup mode
func getRestoredTables(manifest *BackupManifest) []string {
	switch manifest.Mode {
	case ModeConfig:
		return ConfigTables
	case ModeDatabase, ModeFull:
		return FullDatabaseTables
	default:
		return []string{}
	}
}

// orphanResult holds the result of orphan handling
type orphanResult struct {
	found   int
	removed int
	kept    int
}

// handleOrphans processes orphaned file records according to the handling mode
func handleOrphans(opts RestoreOptions, manifest *BackupManifest) (*orphanResult, error) {
	result := &orphanResult{}

	// Get file records from restored database
	records, err := GetFileRecords(opts.DBPath)
	if err != nil {
		return result, fmt.Errorf("failed to get file records: %w", err)
	}

	// All records are orphans since files weren't included in backup
	result.found = len(records)

	if result.found == 0 {
		return result, nil
	}

	switch opts.HandleOrphans {
	case OrphanKeep:
		// Keep all orphans
		result.kept = result.found
		return result, nil

	case OrphanRemove:
		// Remove all orphans
		var storedFilenames []string
		for _, record := range records {
			storedFilenames = append(storedFilenames, record.StoredFilename)
		}

		deleted, err := DeleteOrphanedFileRecords(opts.DBPath, storedFilenames)
		if err != nil {
			return result, fmt.Errorf("failed to delete orphans: %w", err)
		}
		result.removed = deleted
		result.kept = result.found - deleted
		return result, nil

	case OrphanPrompt:
		// Prompt for each orphan
		var toRemove []string
		for _, record := range records {
			keep := opts.OrphanCallback(record.ClaimCode, record.OriginalFilename, record.FileSize)
			if keep {
				result.kept++
			} else {
				toRemove = append(toRemove, record.StoredFilename)
			}
		}

		if len(toRemove) > 0 {
			deleted, err := DeleteOrphanedFileRecords(opts.DBPath, toRemove)
			if err != nil {
				return result, fmt.Errorf("failed to delete selected orphans: %w", err)
			}
			result.removed = deleted
		}
		return result, nil
	}

	return result, nil
}

// performDryRun simulates restore without making changes
func performDryRun(opts RestoreOptions, manifest *BackupManifest, result *RestoreResult, reportProgress func(string)) (*RestoreResult, error) {
	startTime := time.Now()

	reportProgress("Verifying backup integrity...")
	verifyResult := Verify(opts.InputDir)
	if !verifyResult.Valid {
		result.Error = fmt.Sprintf("backup integrity check failed: %v", verifyResult.Errors)
		result.Duration = time.Since(startTime)
		result.DurationString = result.Duration.String()
		return result, nil // Not an error for dry run, just report
	}

	// Check what would be overwritten
	reportProgress("Checking destination paths...")
	if _, err := os.Stat(opts.DBPath); err == nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Database at %s would be overwritten", opts.DBPath))
	}

	// Report what would be restored
	result.TablesRestored = getRestoredTables(manifest)

	if manifest.Includes.Files && manifest.Stats.FilesBackedUp > 0 {
		result.FilesRestored = manifest.Stats.FilesBackedUp
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("%d files would be restored to %s", manifest.Stats.FilesBackedUp, opts.UploadsDir))
	} else if manifest.Includes.FileMetadata && manifest.Stats.FileRecordsCount > 0 {
		result.OrphansFound = manifest.Stats.FileRecordsCount
		switch opts.HandleOrphans {
		case OrphanKeep:
			result.OrphansKept = manifest.Stats.FileRecordsCount
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%d orphaned file records would be kept (metadata only, files not recoverable)", manifest.Stats.FileRecordsCount))
		case OrphanRemove:
			result.OrphansRemoved = manifest.Stats.FileRecordsCount
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%d orphaned file records would be removed", manifest.Stats.FileRecordsCount))
		case OrphanPrompt:
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%d orphaned file records would prompt for decision", manifest.Stats.FileRecordsCount))
		}
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	result.DurationString = result.Duration.String()

	return result, nil
}
