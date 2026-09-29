package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
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
	encryptionKey := flag.String("enckey", "", "64-character hex encryption key (required, except for --verify without --verify-decrypt)")
	dryRun := flag.Bool("dry-run", false, "Preview migration without making changes")
	showVersion := flag.Bool("version", false, "Show version and exit")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	verify := flag.Bool("verify", false, "Read-only: classify every stored file and report problems. Makes no changes to the database or to any file.")
	upgradeFormat := flag.Bool("upgrade-format", false, "Re-seal every SFSE1 file to SFSE2 in place (master finding #10: SFSE1 has no per-chunk AAD). Requires --enckey. Mutually exclusive with --verify. Takes a process-local lock (see README) — does not by itself make it safe to run against files the live server may be serving; see README for guidance.")
	verifyDecrypt := flag.Bool("verify-decrypt", false, "With --verify: also Prime() the first chunk of each SFSE file to check the encryption key. Still read-only.")
	verifyHash := flag.Bool("verify-hash", false, "With --verify: read every byte of every file and check content integrity (AEAD/GCM tags, plus SHA-256 where files.sha256_hash is set). Slow — reads the whole dataset. Still read-only. Implies --verify-decrypt.")
	verifyAll := flag.Bool("all", false, "With --verify: include expired files too (default: non-expired only)")

	flag.Parse()

	// Version check
	if *showVersion {
		fmt.Printf("SafeShare Encryption Migration Tool v%s\n", version)
		os.Exit(0)
	}

	// This tool only supports a local SQLite database and local filesystem
	// uploads directory — refuse early, before touching anything, if the
	// environment says the running server actually uses PostgreSQL and/or
	// S3 (see RequireLocalBackends's doc comment).
	if err := database.RequireLocalBackends(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
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

	if *verify {
		if *upgradeFormat {
			slog.Error("--upgrade-format cannot be combined with --verify")
			os.Exit(1)
		}
		runVerifyCommand(*dbPath, *uploadsDir, *encryptionKey, *verifyAll, *verifyDecrypt, *verifyHash)
		return
	}

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

	// Open database with the same connection setup (busy_timeout,
	// _txlock=immediate, WAL) the live server uses — see
	// database.OpenForCLI's doc comment for why a bare sql.Open here would
	// silently break BeginImmediateTx and fail fast instead of waiting on
	// any lock contended with the running server.
	db, err := database.OpenForCLI(*dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if *upgradeFormat {
		if !*dryRun {
			slog.Warn("--upgrade-format rewrites files in place; safest run during a maintenance window or with the SafeShare server stopped — see README.md's 'Running while the server is up' section for the residual risk if it stays up")
		}
		report, err := runUpgradeFormat(db, *uploadsDir, *encryptionKey, *dryRun)
		if err != nil {
			slog.Error("upgrade-format failed", "error", err)
			os.Exit(1)
		}
		printUpgradeReport(os.Stdout, report, *dryRun)
		if report.Failed > 0 {
			os.Exit(1)
		}
		return
	}

	// Run migration
	if err := migrateEncryption(db, *uploadsDir, *encryptionKey, *dryRun); err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}

	slog.Info("migration completed successfully")
}

// runVerifyCommand implements --verify. It never calls exit-early os.Exit
// paths shared with the migration flow above, so main()'s deferred cleanup
// (none currently held at this point) can't be skipped, and it terminates
// the process itself since it's the last thing main() does on this branch.
func runVerifyCommand(dbPath, uploadsDir, encryptionKey string, includeExpired, verifyDecrypt, verifyHash bool) {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		slog.Error("database file not found", "path", dbPath)
		os.Exit(1)
	}
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		slog.Error("uploads directory not found", "path", uploadsDir)
		os.Exit(1)
	}
	if encryptionKey != "" && !utils.IsEncryptionEnabled(encryptionKey) {
		slog.Error("invalid encryption key", "key_length", len(encryptionKey))
		fmt.Println("Encryption key must be exactly 64 hexadecimal characters (32 bytes), or omitted entirely")
		os.Exit(1)
	}

	// mode=ro opens the database read-only at the SQLite level — --verify
	// must never be able to write, even by accident (no schema creation, no
	// migrations, no pragmas that touch the file).
	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		slog.Error("failed to open database read-only", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	slog.Info("starting verification",
		"db", dbPath,
		"uploads", uploadsDir,
		"include_expired", includeExpired,
		"verify_decrypt", verifyDecrypt || verifyHash,
		"verify_hash", verifyHash,
	)

	report, err := runVerify(db, uploadsDir, encryptionKey, includeExpired, verifyDecrypt, verifyHash)
	if err != nil {
		slog.Error("verification failed", "error", err)
		os.Exit(1)
	}

	printVerifyReport(os.Stdout, report)

	if len(report.Problems) > 0 {
		os.Exit(1)
	}
}

func migrateEncryption(db *sql.DB, uploadsDir, encryptionKey string, dryRun bool) error {
	if !dryRun {
		unlock, err := acquireProcessLock(uploadsDir)
		if err != nil {
			return err
		}
		defer unlock()
	}

	// Get all files from database. Uses the hand-rolled listFilesForVerify
	// query (shared with --verify and --upgrade-format) rather than
	// database.GetAllFiles: this path now needs enc_file_id too, to write a
	// fresh one for every legacy file it re-seals as SFSE2 — see that
	// function's doc comment for why this tool keeps its own query instead
	// of widening the shared helper.
	files, err := listFilesForVerify(db, true)
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
		if err := utils.ValidateStoredFilename(file.StoredFilename); err != nil {
			slog.Error("invalid stored_filename, refusing to touch disk",
				"claim_code", file.ClaimCode, "stored_filename", file.StoredFilename, "error", err)
			failedFiles++
			continue
		}
		filePath := filepath.Join(uploadsDir, file.StoredFilename)

		slog.Debug("processing file",
			"index", i+1,
			"total", totalFiles,
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
			"stored_filename", file.StoredFilename,
		)

		f, err := os.Open(filePath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				slog.Warn("file not found on disk (skipping)", "path", filePath, "claim_code", file.ClaimCode)
			} else {
				slog.Error("failed to open file", "path", filePath, "claim_code", file.ClaimCode, "error", err)
			}
			failedFiles++
			continue
		}
		fi, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			slog.Error("failed to stat file", "path", filePath, "claim_code", file.ClaimCode, "error", statErr)
			failedFiles++
			continue
		}

		// Classify the same way the rest of this tool (and the live claim
		// download path) does, instead of the old ad hoc
		// IsStreamEncrypted/IsEncrypted heuristics — one source of truth
		// for "what format is this file" everywhere in this codebase.
		format, classifyErr := utils.ClassifyStoredFile(f, fi, file.FileSize, true)
		if classifyErr != nil {
			f.Close()
			slog.Error("failed to classify stored file", "path", filePath, "claim_code", file.ClaimCode, "error", classifyErr)
			failedFiles++
			continue
		}

		switch format {
		case utils.FormatSFSE1, utils.FormatSFSE2:
			// Both share the same 5-byte magic; the version byte
			// distinguishes them, which this tool doesn't need to know
			// just to skip an already-migrated file. SFSE1 files are still
			// candidates for `--upgrade-format` — see --verify's
			// "upgradable" count.
			f.Close()
			slog.Debug("file already SFSE-encrypted (skipping)", "claim_code", file.ClaimCode, "filename", file.OriginalFilename)
			sfse1Files++
			continue
		case utils.FormatPlaintext:
			f.Close()
			slog.Debug("file is not encrypted (skipping)", "claim_code", file.ClaimCode, "filename", file.OriginalFilename)
			unencryptedFiles++
			continue
		case utils.FormatLegacy:
			// Falls through to the migration below.
		default:
			f.Close()
			slog.Error("stored file matches no recognized format (skipping)", "path", filePath, "claim_code", file.ClaimCode)
			failedFiles++
			continue
		}

		// File is legacy encrypted - needs migration
		legacyFiles++
		slog.Info("found legacy encrypted file",
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
			"size", fi.Size(),
		)

		if dryRun {
			f.Close()
			slog.Info("DRY RUN: would migrate file to SFSE2 format",
				"claim_code", file.ClaimCode,
				"filename", file.OriginalFilename,
			)
			continue
		}

		// Read the whole ciphertext. Necessarily a whole-buffer operation —
		// legacy predates streaming encryption entirely, so there is no
		// streaming decrypt path to reuse for it; see verify.go's
		// verifyHashLegacyMaxBytes doc comment for the same limitation on
		// the --verify-hash side.
		ciphertext, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			slog.Error("failed to read file", "path", filePath, "claim_code", file.ClaimCode, "error", err)
			failedFiles++
			continue
		}

		slog.Debug("decrypting legacy file", "claim_code", file.ClaimCode)
		plaintext, err := utils.DecryptFile(ciphertext, encryptionKey)
		if err != nil {
			// Decryption failed - file is likely not actually encrypted
			// (ClassifyStoredFile's FormatLegacy match is a size-based
			// heuristic, same underlying limitation IsEncrypted() had)
			slog.Debug("file appears unencrypted (decryption failed)",
				"claim_code", file.ClaimCode,
				"filename", file.OriginalFilename,
			)
			unencryptedFiles++
			legacyFiles-- // Undo the increment from earlier
			continue
		}

		// Verify the decrypted plaintext against the DB row before
		// committing anything — a silent length or content mismatch here
		// would otherwise migrate a file to SFSE2 with a header/DB record
		// that doesn't actually describe its own content.
		if int64(len(plaintext)) != file.FileSize {
			slog.Error("legacy file plaintext length mismatch, refusing to migrate",
				"claim_code", file.ClaimCode, "got_bytes", len(plaintext), "want_bytes", file.FileSize)
			failedFiles++
			continue
		}
		needHash := file.SHA256Hash == ""
		sum := sha256.Sum256(plaintext)
		computedHash := hex.EncodeToString(sum[:])
		if !needHash && computedHash != file.SHA256Hash {
			slog.Error("legacy file plaintext hash mismatch, refusing to migrate",
				"claim_code", file.ClaimCode, "computed", computedHash, "db", file.SHA256Hash)
			failedFiles++
			continue
		}
		newHash := file.SHA256Hash
		if needHash {
			newHash = computedHash
		}

		// Re-encrypt as SFSE2 (not SFSE1 — master finding #10) into a temp
		// file in the same directory, then hand off to commitFormatUpgrade
		// for the crash-safe DB-commit-then-rename swap. See that
		// function's doc comment for the ordering and why it's safe.
		newEncFileID, err := utils.GenerateEncFileID()
		if err != nil {
			slog.Error("failed to generate enc_file_id", "claim_code", file.ClaimCode, "error", err)
			failedFiles++
			continue
		}

		tempPath := filePath + ".sfse2.tmp"
		// Remove any stale temp file left behind by a prior crashed run —
		// see upgradeOneFileToSFSE2's identical comment on the same
		// pattern; safe here for the same reason (this whole function only
		// runs while migrateEncryption holds the process-local flock).
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Error("failed to remove stale temp file", "claim_code", file.ClaimCode, "path", tempPath, "error", err)
			failedFiles++
			continue
		}
		tempFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			slog.Error("failed to create temp file", "claim_code", file.ClaimCode, "path", tempPath, "error", err)
			failedFiles++
			continue
		}

		slog.Debug("re-encrypting with SFSE2 format", "claim_code", file.ClaimCode)
		encErr := utils.EncryptFileStreamingV2FromReader(tempFile, bytes.NewReader(plaintext), encryptionKey, newEncFileID, int64(len(plaintext)))
		var syncErr error
		if encErr == nil {
			// Sync via the same fd we wrote through, before Close — see
			// commitFormatUpgrade's doc comment for why this now has to
			// happen here rather than being redone through a fresh fd
			// later.
			syncErr = tempFile.Sync()
		}
		closeErr := tempFile.Close()
		if encErr != nil {
			slog.Error("failed to re-encrypt file", "claim_code", file.ClaimCode, "error", encErr)
			os.Remove(tempPath)
			failedFiles++
			continue
		}
		if syncErr != nil {
			slog.Error("failed to fsync temp file", "claim_code", file.ClaimCode, "error", syncErr)
			os.Remove(tempPath)
			failedFiles++
			continue
		}
		if closeErr != nil {
			slog.Error("failed to close temp file", "claim_code", file.ClaimCode, "error", closeErr)
			os.Remove(tempPath)
			failedFiles++
			continue
		}

		// Preserve the original file's mode (and, when running as root,
		// its owner/group) on the re-encrypted temp file — see
		// preserveFileOwnership's doc comment.
		if err := preserveFileOwnership(tempPath, fi); err != nil {
			slog.Error("failed to preserve file ownership", "claim_code", file.ClaimCode, "error", err)
			os.Remove(tempPath)
			failedFiles++
			continue
		}

		newInfo, _ := os.Stat(tempPath)

		if err := commitFormatUpgrade(db, uploadsDir, filePath, tempPath, file.ID, file.StoredFilename, newEncFileID, newHash, needHash, crashNone); err != nil {
			os.Remove(tempPath)
			if errors.Is(err, errFinalPathVanishedDuringCommit) {
				// Not a failure: the row (and its file) were deleted
				// concurrently — most plausibly by expiry cleanup — while
				// we were re-encrypting it. Nothing left to migrate.
				slog.Info("file expired during migration (skipping)", "claim_code", file.ClaimCode, "filename", file.OriginalFilename)
				legacyFiles-- // undo the increment from earlier — this was never actually migrated
				continue
			}
			slog.Error("failed to commit migrated file", "claim_code", file.ClaimCode, "error", err)
			failedFiles++
			continue
		}

		migratedFiles++
		slog.Info("successfully migrated file to SFSE2",
			"claim_code", file.ClaimCode,
			"filename", file.OriginalFilename,
			"original_size", len(plaintext),
			"new_size", newInfo.Size(),
		)
	}

	// Print summary
	fmt.Println("\n=== Migration Summary ===")
	fmt.Printf("Total files in database: %d\n", totalFiles)
	fmt.Printf("Already SFSE format:     %d\n", sfse1Files)
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
