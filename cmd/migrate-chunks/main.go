package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fjmerc/safeshare/internal/utils"
)

const (
	oldChunkSize = 64 * 1024 * 1024 // 64MB
	newChunkSize = 10 * 1024 * 1024 // 10MB
)

type MigrationStats struct {
	TotalFiles      int
	AlreadyMigrated int
	NeedsMigration  int
	Migrated        int
	Failed          int
	SkippedNonSFSE  int
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// run is the main entry point that can be tested (returns error instead of calling os.Exit)
func run(args []string) error {
	// Parse command-line flags
	fs := flag.NewFlagSet("migrate-chunks", flag.ContinueOnError)
	uploadDir := fs.String("upload-dir", "./uploads", "Upload directory path")
	encKey := fs.String("encryption-key", "", "64-character hex encryption key (required)")
	dryRun := fs.Bool("dry-run", false, "Preview what would be migrated without making changes")
	verbose := fs.Bool("verbose", false, "Enable verbose debug logging")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Setup logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Validate flags
	if *encKey == "" {
		return fmt.Errorf("--encryption-key is required")
	}
	if !utils.IsEncryptionEnabled(*encKey) {
		return fmt.Errorf("encryption key must be 64 hex characters")
	}

	// Validate upload directory exists and is a directory
	info, err := os.Stat(*uploadDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("upload directory does not exist: %s", *uploadDir)
		}
		return fmt.Errorf("failed to access upload directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("upload path is not a directory: %s", *uploadDir)
	}

	slog.Info("Starting SFSE1 chunk size migration",
		"upload_dir", *uploadDir,
		"dry_run", *dryRun,
		"old_chunk_size_mb", oldChunkSize/(1024*1024),
		"new_chunk_size_mb", newChunkSize/(1024*1024))

	// Scan upload directory
	stats := &MigrationStats{}
	startTime := time.Now()

	err = filepath.Walk(*uploadDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			slog.Warn("Failed to access path", "path", path, "error", err)
			return nil // Continue walking
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip hidden files and directories (e.g., .partial/)
		if len(info.Name()) > 0 && info.Name()[0] == '.' {
			return nil
		}

		stats.TotalFiles++

		// Check if file is SFSE1 encrypted
		isEncrypted, err := utils.IsStreamEncrypted(path)
		if err != nil {
			slog.Warn("Failed to check if file is encrypted", "path", path, "error", err)
			stats.SkippedNonSFSE++
			return nil
		}

		if !isEncrypted {
			slog.Debug("Skipping non-SFSE1 file", "path", path)
			stats.SkippedNonSFSE++
			return nil
		}

		// Read current chunk size
		chunkSize, err := readChunkSize(path)
		if err != nil {
			slog.Warn("Failed to read chunk size", "path", path, "error", err)
			stats.Failed++
			return nil
		}

		slog.Debug("File chunk size", "path", path, "chunk_size_mb", chunkSize/(1024*1024))

		// Check if migration needed
		if chunkSize == newChunkSize {
			slog.Debug("File already using new chunk size", "path", path)
			stats.AlreadyMigrated++
			return nil
		}

		if chunkSize != oldChunkSize {
			slog.Warn("File has unexpected chunk size, skipping",
				"path", path,
				"chunk_size_mb", chunkSize/(1024*1024))
			stats.SkippedNonSFSE++
			return nil
		}

		// File needs migration
		stats.NeedsMigration++
		slog.Info("File needs migration",
			"path", path,
			"size_mb", info.Size()/(1024*1024),
			"old_chunk_mb", oldChunkSize/(1024*1024),
			"new_chunk_mb", newChunkSize/(1024*1024))

		if *dryRun {
			slog.Info("DRY RUN: Would migrate file", "path", path)
			return nil
		}

		// Perform migration
		if err := migrateFile(path, *encKey); err != nil {
			slog.Error("Migration failed", "path", path, "error", err)
			stats.Failed++
			return nil
		}

		stats.Migrated++
		slog.Info("Successfully migrated file", "path", path)

		return nil
	})

	if err != nil {
		return fmt.Errorf("walking upload directory: %w", err)
	}

	// Print summary
	duration := time.Since(startTime)
	slog.Info("Migration completed",
		"duration_seconds", duration.Seconds(),
		"total_files", stats.TotalFiles,
		"already_migrated", stats.AlreadyMigrated,
		"needs_migration", stats.NeedsMigration,
		"migrated", stats.Migrated,
		"failed", stats.Failed,
		"skipped_non_sfse", stats.SkippedNonSFSE,
		"dry_run", *dryRun)

	if *dryRun {
		fmt.Println("\n=== DRY RUN COMPLETE ===")
		fmt.Printf("Would migrate %d files from 64MB to 10MB chunks\n", stats.NeedsMigration)
		fmt.Println("Run without --dry-run to perform actual migration")
	} else {
		fmt.Println("\n=== MIGRATION COMPLETE ===")
		fmt.Printf("Successfully migrated: %d files\n", stats.Migrated)
		fmt.Printf("Failed: %d files\n", stats.Failed)
	}

	if stats.Failed > 0 {
		return fmt.Errorf("migration had %d failures", stats.Failed)
	}

	return nil
}

// readChunkSize reads the chunk size from an SFSE1 file header
func readChunkSize(path string) (uint32, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Skip magic (5 bytes) and version (1 byte)
	if _, err := file.Seek(6, io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to chunk size: %w", err)
	}

	// Read chunk size (4 bytes, little endian)
	chunkSizeBytes := make([]byte, 4)
	if _, err := io.ReadFull(file, chunkSizeBytes); err != nil {
		return 0, fmt.Errorf("failed to read chunk size: %w", err)
	}

	chunkSize := binary.LittleEndian.Uint32(chunkSizeBytes)
	return chunkSize, nil
}

// migrateFile re-encrypts a file from 64MB chunks to 10MB chunks
func migrateFile(path string, encKey string) error {
	startTime := time.Now()

	// Step 1: Decrypt to temporary file
	tempDecrypted := path + ".decrypted.tmp"
	slog.Debug("Decrypting to temp file", "src", path, "dst", tempDecrypted)

	if err := utils.DecryptFileStreaming(path, tempDecrypted, encKey); err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}
	defer os.Remove(tempDecrypted) // Clean up temp file

	decryptDuration := time.Since(startTime)
	slog.Debug("Decryption complete", "duration_seconds", decryptDuration.Seconds())

	// Step 2: Encrypt with new chunk size to another temp file
	tempEncrypted := path + ".encrypted.tmp"
	defer os.Remove(tempEncrypted) // Clean up temp file on error
	encryptStart := time.Now()
	slog.Debug("Encrypting with new chunk size", "src", tempDecrypted, "dst", tempEncrypted)

	if err := utils.EncryptFileStreaming(tempDecrypted, tempEncrypted, encKey); err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	encryptDuration := time.Since(encryptStart)
	slog.Debug("Encryption complete", "duration_seconds", encryptDuration.Seconds())

	// Step 3: Atomic replace - rename temp file to original
	// First, create backup of original
	backupPath := path + ".backup"
	if err := os.Rename(path, backupPath); err != nil {
		// tempEncrypted will be cleaned up by defer
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Rename new file to original path
	if err := os.Rename(tempEncrypted, path); err != nil {
		// Restore backup on failure
		os.Rename(backupPath, path)
		return fmt.Errorf("failed to rename migrated file: %w", err)
	}

	// Remove backup on success
	os.Remove(backupPath)

	totalDuration := time.Since(startTime)
	slog.Debug("Migration complete",
		"total_duration_seconds", totalDuration.Seconds(),
		"decrypt_duration_seconds", decryptDuration.Seconds(),
		"encrypt_duration_seconds", encryptDuration.Seconds())

	return nil
}
