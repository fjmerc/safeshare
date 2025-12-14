package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Verify checks the integrity of a backup
func Verify(backupDir string) *VerifyResult {
	result := &VerifyResult{
		Errors:   []string{},
		Warnings: []string{},
	}

	// Check backup directory exists
	if _, err := os.Stat(backupDir); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Backup directory not accessible: %v", err))
		return result
	}

	// Step 1: Read and validate manifest
	manifest, err := ReadManifest(backupDir)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read manifest: %v", err))
		return result
	}
	result.Manifest = manifest
	result.ManifestValid = true

	// Validate manifest structure
	if err := ValidateManifest(manifest); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid manifest: %v", err))
		result.ManifestValid = false
		return result
	}

	// Step 2: Verify database file exists and is valid
	dbPath := filepath.Join(backupDir, DatabaseFilename)
	if _, err := os.Stat(dbPath); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Database file not found: %v", err))
	} else {
		// Validate database integrity
		if err := ValidateDatabase(dbPath); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Database integrity check failed: %v", err))
		} else {
			result.DatabaseValid = true
		}
	}

	// Get absolute backup directory for path traversal protection
	absBackupDir, err := filepath.Abs(backupDir)
	if err != nil {
		result.Errors = append(result.Errors, "Invalid backup directory path")
		return result
	}

	// Step 3: Verify checksums
	result.ChecksumsValid = true
	for file, expectedChecksum := range manifest.Checksums {
		// Security: Validate path from manifest to prevent path traversal
		if strings.Contains(file, "..") || filepath.IsAbs(file) {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid path in manifest: %s", file))
			result.ChecksumsValid = false
			continue
		}

		filePath := filepath.Join(backupDir, file)

		// Security: Verify path is within backupDir (defense in depth)
		absFilePath, err := filepath.Abs(filePath)
		if err != nil || !strings.HasPrefix(absFilePath, absBackupDir+string(filepath.Separator)) {
			result.Errors = append(result.Errors, fmt.Sprintf("Path traversal in manifest: %s", file))
			result.ChecksumsValid = false
			continue
		}

		// Check file exists
		if _, err := os.Stat(filePath); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("File not found: %s", file))
			result.MissingFiles = append(result.MissingFiles, file)
			result.ChecksumsValid = false
			continue
		}

		// Verify checksum
		actualChecksum, err := ComputeChecksum(filePath)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to compute checksum for %s: %v", file, err))
			result.ChecksumsValid = false
			continue
		}

		if actualChecksum != expectedChecksum {
			result.ChecksumsValid = false
			result.ChecksumMismatches = append(result.ChecksumMismatches, ChecksumMismatch{
				File:     file,
				Expected: expectedChecksum,
				Actual:   actualChecksum,
			})
		}
	}

	// Step 4: For full backups, verify all expected files are present
	if manifest.Mode == ModeFull && manifest.Includes.Files {
		result.FilesValid = true
		uploadsDir := filepath.Join(backupDir, UploadsDirname)

		if _, err := os.Stat(uploadsDir); err != nil {
			if manifest.Stats.FilesBackedUp > 0 {
				result.Errors = append(result.Errors, "Uploads directory not found but files were expected")
				result.FilesValid = false
			}
		} else {
			// Count files in uploads directory
			files, err := listFiles(uploadsDir)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to list uploads: %v", err))
				result.FilesValid = false
			} else {
				actualCount := len(files)
				expectedCount := manifest.Stats.FilesBackedUp

				if actualCount != expectedCount {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("File count mismatch: expected %d, found %d", expectedCount, actualCount))
				}
			}
		}
	} else {
		// Not a full backup, files validity is N/A
		result.FilesValid = true
	}

	// Determine overall validity
	result.Valid = result.ManifestValid &&
		result.DatabaseValid &&
		result.ChecksumsValid &&
		result.FilesValid &&
		len(result.Errors) == 0

	return result
}

// QuickVerify performs a fast verification without checksum validation
func QuickVerify(backupDir string) *VerifyResult {
	result := &VerifyResult{
		Errors:   []string{},
		Warnings: []string{},
	}

	// Check backup directory exists
	if _, err := os.Stat(backupDir); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Backup directory not accessible: %v", err))
		return result
	}

	// Read manifest
	manifest, err := ReadManifest(backupDir)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read manifest: %v", err))
		return result
	}
	result.Manifest = manifest
	result.ManifestValid = true

	// Check database file exists
	dbPath := filepath.Join(backupDir, DatabaseFilename)
	if _, err := os.Stat(dbPath); err != nil {
		result.Errors = append(result.Errors, "Database file not found")
	} else {
		result.DatabaseValid = true
	}

	// Skip checksum verification in quick mode
	result.ChecksumsValid = true
	result.Warnings = append(result.Warnings, "Checksum verification skipped (quick mode)")

	// Check uploads directory for full backups
	if manifest.Mode == ModeFull && manifest.Stats.FilesBackedUp > 0 {
		uploadsDir := filepath.Join(backupDir, UploadsDirname)
		if _, err := os.Stat(uploadsDir); err != nil {
			result.Errors = append(result.Errors, "Uploads directory not found")
			result.FilesValid = false
		} else {
			result.FilesValid = true
		}
	} else {
		result.FilesValid = true
	}

	// Determine overall validity
	result.Valid = result.ManifestValid &&
		result.DatabaseValid &&
		result.FilesValid &&
		len(result.Errors) == 0

	return result
}

// VerifyWithProgress performs verification with progress callbacks
func VerifyWithProgress(backupDir string, progressCallback func(current, total int, description string)) *VerifyResult {
	result := &VerifyResult{
		Errors:   []string{},
		Warnings: []string{},
	}

	totalSteps := 4 // manifest, database, checksums, files
	currentStep := 0

	reportProgress := func(description string) {
		currentStep++
		if progressCallback != nil {
			progressCallback(currentStep, totalSteps, description)
		}
	}

	// Step 1: Read and validate manifest
	reportProgress("Reading manifest...")
	manifest, err := ReadManifest(backupDir)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to read manifest: %v", err))
		return result
	}
	result.Manifest = manifest

	if err := ValidateManifest(manifest); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid manifest: %v", err))
		return result
	}
	result.ManifestValid = true

	// Step 2: Validate database
	reportProgress("Validating database...")
	dbPath := filepath.Join(backupDir, DatabaseFilename)
	if err := ValidateDatabase(dbPath); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Database validation failed: %v", err))
	} else {
		result.DatabaseValid = true
	}

	// Step 3: Verify checksums
	reportProgress("Verifying checksums...")
	result.ChecksumsValid = true
	for file, expectedChecksum := range manifest.Checksums {
		filePath := filepath.Join(backupDir, file)

		if err := VerifyChecksum(filePath, expectedChecksum); err != nil {
			result.ChecksumsValid = false
			if os.IsNotExist(err) {
				result.MissingFiles = append(result.MissingFiles, file)
			} else {
				// Parse actual checksum from error or compute it
				actualChecksum, _ := ComputeChecksum(filePath)
				result.ChecksumMismatches = append(result.ChecksumMismatches, ChecksumMismatch{
					File:     file,
					Expected: expectedChecksum,
					Actual:   actualChecksum,
				})
			}
		}
	}

	// Step 4: Verify files
	reportProgress("Verifying files...")
	if manifest.Mode == ModeFull && manifest.Includes.Files {
		uploadsDir := filepath.Join(backupDir, UploadsDirname)
		if _, err := os.Stat(uploadsDir); err != nil {
			if manifest.Stats.FilesBackedUp > 0 {
				result.Errors = append(result.Errors, "Uploads directory missing")
				result.FilesValid = false
			} else {
				result.FilesValid = true
			}
		} else {
			result.FilesValid = true
		}
	} else {
		result.FilesValid = true
	}

	// Determine overall validity
	result.Valid = result.ManifestValid &&
		result.DatabaseValid &&
		result.ChecksumsValid &&
		result.FilesValid &&
		len(result.Errors) == 0

	return result
}
