package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/utils"
	_ "modernc.org/sqlite"
)

const version = "1.0.0"

func main() {
	// Command-line flags
	dbPath := flag.String("db", "./safeshare.db", "Path to SQLite database")
	uploadsDir := flag.String("uploads", "./uploads", "Path to uploads directory")
	encryptionKey := flag.String("enckey", "", "64-character hex encryption key (required)")
	dryRun := flag.Bool("dry-run", false, "Preview migration without making changes")
	showVersion := flag.Bool("version", false, "Show version and exit")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")

	flag.Parse()

	// Version check
	if *showVersion {
		fmt.Printf("SafeShare Encryption Migration Tool v%s\n", version)
		os.Exit(0)
	}

	// Configure logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Validate required flags
	if *encryptionKey == "" {
		slog.Error("encryption key is required")
		fmt.Println("\nUsage: migrate-encryption --db <path> --uploads <path> --enckey <key>")
		fmt.Println("       migrate-encryption --help")
		os.Exit(1)
	}

	// Validate encryption key format
	if !utils.IsEncryptionEnabled(*encryptionKey) {
		slog.Error("invalid encryption key", "key_length", len(*encryptionKey))
		fmt.Println("Encryption key must be exactly 64 hexadecimal characters (32 bytes)")
		fmt.Println("Generate a key with: openssl rand -hex 32")
		os.Exit(1)
	}

	// Validate paths
	if _, err := os.Stat(*dbPath); os.IsNotExist(err) {
		slog.Error("database file not found", "path", *dbPath)
		os.Exit(1)
	}

	if _, err := os.Stat(*uploadsDir); os.IsNotExist(err) {
		slog.Error("uploads directory not found", "path", *uploadsDir)
		os.Exit(1)
	}

	slog.Info("starting encryption migration",
		"db", *dbPath,
		"uploads", *uploadsDir,
		"dry_run", *dryRun,
	)

	// Open database
	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Run migration
	if err := migrateEncryption(db, *uploadsDir, *encryptionKey, *dryRun); err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}

	slog.Info("migration completed successfully")
}

func migrateEncryption(db *sql.DB, uploadsDir, encryptionKey string, dryRun bool) error {
	// Get all files from database
	files, err := database.GetAllFiles(db)
	if err != nil {
		return fmt.Errorf("failed to get files: %w", err)
	}

	slog.Info("found files in database", "count", len(files))

	if len(files) == 0 {
		slog.Info("no files to migrate")
		return nil
	}

	// Statistics
	var (
		totalFiles       = len(files)
		legacyFiles      = 0
		sfse1Files       = 0
		unencryptedFiles = 0
		migratedFiles    = 0
		failedFiles      = 0
	)

	// Process each file
	for i, file := range files {
		filePath := filepath.Join(uploadsDir, file.StoredFilename)

		slog.Debug("processing file",
			"index", i+1,
			"total", totalFiles,
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
			"stored_filename", file.StoredFilename,
		)

		// Check if file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			slog.Warn("file not found on disk (skipping)",
				"path", filePath,
				"claim_code", file.ClaimCode,
			)
			failedFiles++
			continue
		}

		// Check if file is SFSE1 encrypted
		isStreamEnc, err := utils.IsStreamEncrypted(filePath)
		if err != nil {
			slog.Error("failed to check encryption format",
				"path", filePath,
				"error", err,
			)
			failedFiles++
			continue
		}

		if isStreamEnc {
			// Already SFSE1 format
			slog.Debug("file already in SFSE1 format (skipping)",
				"claim_code", file.ClaimCode,
				"filename", file.OriginalFilename,
			)
			sfse1Files++
			continue
		}

		// Read file to check if it's legacy encrypted
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			slog.Error("failed to read file", "path", filePath, "error", err)
			failedFiles++
			continue
		}

		// Check if file is legacy encrypted
		if !utils.IsEncrypted(fileData) {
			// Not encrypted at all
			slog.Debug("file is not encrypted (skipping)",
				"claim_code", file.ClaimCode,
				"filename", file.OriginalFilename,
			)
			unencryptedFiles++
			continue
		}

		// File is legacy encrypted - needs migration
		legacyFiles++
		slog.Info("found legacy encrypted file",
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
			"size", len(fileData),
		)

		if dryRun {
			slog.Info("DRY RUN: would migrate file to SFSE1 format",
				"claim_code", file.ClaimCode,
				"filename", file.OriginalFilename,
			)
			continue
		}

		// Decrypt using legacy method
		slog.Debug("decrypting legacy file", "claim_code", file.ClaimCode)
		plaintext, err := utils.DecryptFile(fileData, encryptionKey)
		if err != nil {
			// Decryption failed - file is likely not actually encrypted
			// (IsEncrypted() only checks file size, not actual encryption)
			slog.Debug("file appears unencrypted (decryption failed)",
				"claim_code", file.ClaimCode,
				"filename", file.OriginalFilename,
			)
			unencryptedFiles++
			legacyFiles-- // Undo the increment from earlier
			continue
		}

		// Create temporary file for SFSE1 encrypted version
		tempPath := filePath + ".sfse1.tmp"

		// Write plaintext to temporary file first (needed for streaming encryption)
		tempPlainPath := filePath + ".plain.tmp"
		if err := os.WriteFile(tempPlainPath, plaintext, 0600); err != nil {
			slog.Error("failed to write temporary plaintext file",
				"claim_code", file.ClaimCode,
				"error", err,
			)
			os.Remove(tempPlainPath)
			failedFiles++
			continue
		}

		// Re-encrypt using SFSE1 streaming encryption
		slog.Debug("re-encrypting with SFSE1 format", "claim_code", file.ClaimCode)
		if err := utils.EncryptFileStreaming(tempPlainPath, tempPath, encryptionKey); err != nil {
			slog.Error("failed to re-encrypt file",
				"claim_code", file.ClaimCode,
				"error", err,
			)
			os.Remove(tempPlainPath)
			os.Remove(tempPath)
			failedFiles++
			continue
		}

		// Remove temporary plaintext file
		os.Remove(tempPlainPath)

		// Get file sizes for logging
		originalInfo, _ := os.Stat(filePath)
		newInfo, _ := os.Stat(tempPath)

		// Replace original file with SFSE1 version
		if err := os.Remove(filePath); err != nil {
			slog.Error("failed to remove original file",
				"claim_code", file.ClaimCode,
				"error", err,
			)
			os.Remove(tempPath)
			failedFiles++
			continue
		}

		if err := os.Rename(tempPath, filePath); err != nil {
			slog.Error("failed to rename migrated file",
				"claim_code", file.ClaimCode,
				"error", err,
			)
			// Original file is already deleted - this is a critical error
			// But we can't recover, so just log and continue
			failedFiles++
			continue
		}

		migratedFiles++
		slog.Info("successfully migrated file to SFSE1",
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
			"original_size", originalInfo.Size(),
			"new_size", newInfo.Size(),
		)
	}

	// Print summary
	fmt.Println("\n=== Migration Summary ===")
	fmt.Printf("Total files in database: %d\n", totalFiles)
	fmt.Printf("Already SFSE1 format:    %d\n", sfse1Files)
	fmt.Printf("Unencrypted files:       %d\n", unencryptedFiles)
	fmt.Printf("Legacy encrypted files:  %d\n", legacyFiles)
	if dryRun {
		fmt.Printf("Would migrate:           %d\n", legacyFiles)
	} else {
		fmt.Printf("Successfully migrated:   %d\n", migratedFiles)
		fmt.Printf("Failed migrations:       %d\n", failedFiles)
	}

	if failedFiles > 0 && !dryRun {
		return fmt.Errorf("%d file(s) failed to migrate", failedFiles)
	}

	return nil
}
