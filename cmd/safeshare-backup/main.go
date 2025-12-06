package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/backup"
)

// Version information
const (
	ToolVersion = "1.0.0"
	ToolName    = "SafeShare Backup Tool"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Handle top-level flags
	if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage()
		os.Exit(0)
	}

	if os.Args[1] == "-v" || os.Args[1] == "--version" || os.Args[1] == "version" {
		fmt.Printf("%s v%s\n", ToolName, ToolVersion)
		os.Exit(0)
	}

	// Parse subcommand
	var err error
	switch os.Args[1] {
	case "create":
		err = runCreate(os.Args[2:])
	case "restore":
		err = runRestore(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "list":
		err = runList(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`%s v%s

A comprehensive backup and restore utility for SafeShare.

USAGE:
    safeshare-backup <command> [options]

COMMANDS:
    create      Create a new backup
    restore     Restore from a backup
    verify      Verify backup integrity
    list        List available backups

FLAGS:
    -h, --help      Show this help message
    -v, --version   Show version information

EXAMPLES:
    # Create a full backup
    safeshare-backup create --mode full --db /app/data/safeshare.db \
        --uploads /app/uploads --output /backups

    # Create a database-only backup
    safeshare-backup create --mode database --db /app/data/safeshare.db \
        --output /backups

    # Restore from a backup (with preview)
    safeshare-backup restore --backup /backups/backup-20240101-120000 \
        --db /app/data/safeshare.db --uploads /app/uploads --dry-run

    # Verify backup integrity
    safeshare-backup verify --backup /backups/backup-20240101-120000

    # List all backups
    safeshare-backup list --dir /backups

For more information on a command, run:
    safeshare-backup <command> --help
`, ToolName, ToolVersion)
}

// runCreate handles the "create" subcommand
func runCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)

	// Required flags
	mode := fs.String("mode", "full", "Backup mode: config, database, or full")
	dbPath := fs.String("db", "", "Path to SafeShare database (required)")
	outputDir := fs.String("output", "", "Output directory for backups (required)")

	// Optional flags
	uploadsDir := fs.String("uploads", "", "Path to uploads directory (required for full mode)")
	encKey := fs.String("enckey", "", "Encryption key for key fingerprinting (64 hex chars)")
	quiet := fs.Bool("quiet", false, "Minimal output")
	jsonOutput := fs.Bool("json", false, "JSON output format")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Create a new SafeShare backup.

USAGE:
    safeshare-backup create [options]

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
BACKUP MODES:
    config      Settings only (app_settings, webhooks tables)
    database    Full database backup (all tables)
    full        Database + all uploaded files

EXAMPLES:
    # Full backup (database + files)
    safeshare-backup create --mode full --db /app/data/safeshare.db \
        --uploads /app/uploads --output /backups

    # Database-only backup
    safeshare-backup create --mode database --db /app/data/safeshare.db \
        --output /backups

    # Config backup with custom prefix
    safeshare-backup create --mode config --db /app/data/safeshare.db \
        --output /backups
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required flags
	if *dbPath == "" {
		return fmt.Errorf("--db flag is required")
	}
	if *outputDir == "" {
		return fmt.Errorf("--output flag is required")
	}

	// Parse backup mode
	var backupMode backup.BackupMode
	switch strings.ToLower(*mode) {
	case "config":
		backupMode = backup.ModeConfig
	case "database", "db":
		backupMode = backup.ModeDatabase
	case "full":
		backupMode = backup.ModeFull
	default:
		return fmt.Errorf("invalid backup mode: %s (must be config, database, or full)", *mode)
	}

	// Full mode requires uploads directory
	if backupMode == backup.ModeFull && *uploadsDir == "" {
		return fmt.Errorf("--uploads flag is required for full backup mode")
	}

	// Validate paths exist
	if _, err := os.Stat(*dbPath); err != nil {
		return fmt.Errorf("cannot access database: %w", err)
	}
	if backupMode == backup.ModeFull {
		if _, err := os.Stat(*uploadsDir); err != nil {
			return fmt.Errorf("cannot access uploads directory: %w", err)
		}
	}
	if _, err := os.Stat(*outputDir); err != nil {
		return fmt.Errorf("cannot access output directory: %w", err)
	}

	// Create backup options
	opts := backup.CreateOptions{
		Mode:             backupMode,
		DBPath:           *dbPath,
		UploadsDir:       *uploadsDir,
		OutputDir:        *outputDir,
		EncryptionKey:    *encKey,
		SafeShareVersion: ToolVersion,
	}

	// Print start message
	if !*quiet && !*jsonOutput {
		fmt.Printf("Creating %s backup...\n", *mode)
		fmt.Printf("  Database: %s\n", *dbPath)
		if backupMode == backup.ModeFull {
			fmt.Printf("  Uploads:  %s\n", *uploadsDir)
		}
		fmt.Printf("  Output:   %s\n", *outputDir)
		fmt.Println()
	}

	// Create backup
	result, err := backup.Create(opts)

	// Output result
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		encErr := enc.Encode(result)
		if encErr != nil {
			return encErr
		}
		if err != nil {
			return err
		}
		return nil
	}

	if !*quiet {
		printCreateResult(result)
	}

	return err
}

// runRestore handles the "restore" subcommand
func runRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)

	// Required flags
	backupPath := fs.String("backup", "", "Path to backup directory (required)")
	dbPath := fs.String("db", "", "Path to restore database to (required)")

	// Optional flags
	uploadsDir := fs.String("uploads", "", "Path to restore uploads to (required for full backup)")
	encKey := fs.String("enckey", "", "Encryption key for verification (64 hex chars)")
	orphans := fs.String("orphans", "keep", "Orphan handling: keep, remove, or prompt")
	dryRun := fs.Bool("dry-run", false, "Preview restore without making changes")
	force := fs.Bool("force", false, "Overwrite existing data without confirmation")
	quiet := fs.Bool("quiet", false, "Minimal output")
	jsonOutput := fs.Bool("json", false, "JSON output format")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Restore SafeShare from a backup.

USAGE:
    safeshare-backup restore [options]

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
ORPHAN HANDLING:
    When restoring a database-only backup, files referenced in the database
    may not exist in the uploads directory. These are "orphan" references.

    keep    Keep orphan database records (downloads will fail gracefully)
    remove  Delete orphan records from the restored database
    prompt  Interactive prompt for each orphan (not available with --json)

EXAMPLES:
    # Restore with preview
    safeshare-backup restore --backup /backups/backup-20240101-120000 \
        --db /app/data/safeshare.db --uploads /app/uploads --dry-run

    # Restore removing orphans
    safeshare-backup restore --backup /backups/backup-20240101-120000 \
        --db /app/data/safeshare.db --orphans remove

    # Restore with encryption key verification
    safeshare-backup restore --backup /backups/backup-20240101-120000 \
        --db /app/data/safeshare.db --enckey "your-64-char-hex-key"
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required flags
	if *backupPath == "" {
		return fmt.Errorf("--backup flag is required")
	}
	if *dbPath == "" {
		return fmt.Errorf("--db flag is required")
	}

	// Validate backup path exists
	if _, err := os.Stat(*backupPath); err != nil {
		return fmt.Errorf("cannot access backup: %w", err)
	}

	// Parse orphan handling
	var orphanHandling backup.OrphanHandling
	switch strings.ToLower(*orphans) {
	case "keep":
		orphanHandling = backup.OrphanKeep
	case "remove":
		orphanHandling = backup.OrphanRemove
	case "prompt":
		if *jsonOutput {
			return fmt.Errorf("orphan=prompt is not available with --json output")
		}
		orphanHandling = backup.OrphanPrompt
	default:
		return fmt.Errorf("invalid orphan handling: %s (must be keep, remove, or prompt)", *orphans)
	}

	// Create restore options
	opts := backup.RestoreOptions{
		InputDir:      *backupPath,
		DBPath:        *dbPath,
		UploadsDir:    *uploadsDir,
		EncryptionKey: *encKey,
		HandleOrphans: orphanHandling,
		DryRun:        *dryRun,
		Force:         *force,
	}

	// Print start message
	if !*quiet && !*jsonOutput {
		fmt.Printf("Restoring from backup...\n")
		fmt.Printf("  Backup: %s\n", *backupPath)
		fmt.Printf("  Target DB: %s\n", *dbPath)
		if *uploadsDir != "" {
			fmt.Printf("  Target Uploads: %s\n", *uploadsDir)
		}
		if *dryRun {
			fmt.Println("  Mode: DRY RUN (no changes will be made)")
		}
		fmt.Println()
	}

	// Perform restore
	result, err := backup.Restore(opts)

	// Output result
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		encErr := enc.Encode(result)
		if encErr != nil {
			return encErr
		}
		if err != nil {
			return err
		}
		return nil
	}

	if !*quiet {
		printRestoreResult(result)
	}

	return err
}

// runVerify handles the "verify" subcommand
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)

	// Required flags
	backupPath := fs.String("backup", "", "Path to backup directory (required)")

	// Optional flags
	quiet := fs.Bool("quiet", false, "Minimal output")
	jsonOutput := fs.Bool("json", false, "JSON output format")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Verify SafeShare backup integrity.

USAGE:
    safeshare-backup verify [options]

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
VERIFICATION CHECKS:
    - Manifest file exists and is valid JSON
    - All files listed in manifest exist
    - SHA256 checksums match for all files
    - Backup mode is valid
    - Required files present for backup mode

EXAMPLES:
    # Verify a backup
    safeshare-backup verify --backup /backups/backup-20240101-120000

    # Verify with JSON output
    safeshare-backup verify --backup /backups/backup-20240101-120000 --json
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required flags
	if *backupPath == "" {
		return fmt.Errorf("--backup flag is required")
	}

	// Validate backup path exists
	if _, err := os.Stat(*backupPath); err != nil {
		return fmt.Errorf("cannot access backup: %w", err)
	}

	// Print start message
	if !*quiet && !*jsonOutput {
		fmt.Printf("Verifying backup integrity...\n")
		fmt.Printf("  Backup: %s\n", *backupPath)
		fmt.Println()
	}

	// Perform verification
	result := backup.Verify(*backupPath)

	// Output result
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	if !*quiet {
		printVerifyResult(result)
	}

	if !result.Valid {
		return fmt.Errorf("backup verification failed")
	}

	return nil
}

// runList handles the "list" subcommand
func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)

	// Required flags
	dir := fs.String("dir", "", "Directory containing backups (required)")

	// Optional flags
	jsonOutput := fs.Bool("json", false, "JSON output format")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `List available SafeShare backups.

USAGE:
    safeshare-backup list [options]

OPTIONS:
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
    # List all backups
    safeshare-backup list --dir /backups

    # List backups with JSON output
    safeshare-backup list --dir /backups --json
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required flags
	if *dir == "" {
		return fmt.Errorf("--dir flag is required")
	}

	// Validate directory exists
	if _, err := os.Stat(*dir); err != nil {
		return fmt.Errorf("cannot access directory: %w", err)
	}

	// List backups
	backups, err := backup.ListBackups(*dir)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	// Output result
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(backups)
	}

	printBackupList(backups)
	return nil
}

// printCreateResult displays backup creation result
func printCreateResult(result *backup.BackupResult) {
	fmt.Println("======================================================================")
	if result.Success {
		fmt.Println("BACKUP CREATED SUCCESSFULLY")
	} else {
		fmt.Println("BACKUP FAILED")
	}
	fmt.Println("======================================================================")

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
		return
	}

	fmt.Printf("Backup Path:     %s\n", result.BackupPath)
	if result.Manifest != nil {
		fmt.Printf("Mode:            %s\n", result.Manifest.Mode)
		fmt.Printf("Created At:      %s\n", result.Manifest.CreatedAt.Format(time.RFC3339))
		fmt.Printf("Database Size:   %s\n", formatBytes(result.Manifest.Stats.DatabaseSizeBytes))

		if result.Manifest.Mode == backup.ModeFull {
			fmt.Printf("Upload Files:    %d\n", result.Manifest.Stats.FilesBackedUp)
			fmt.Printf("Uploads Size:    %s\n", formatBytes(result.Manifest.Stats.FilesSizeBytes))
		}

		fmt.Printf("Total Size:      %s\n", formatBytes(result.Manifest.Stats.TotalSizeBytes))

		if result.Manifest.Encryption.Enabled && result.Manifest.Encryption.KeyFingerprint != "" {
			fingerprint := result.Manifest.Encryption.KeyFingerprint
			if len(fingerprint) > 16 {
				fingerprint = fingerprint[:16] + "..."
			}
			fmt.Printf("Key Fingerprint: %s\n", fingerprint)
		}
	}
	fmt.Printf("Duration:        %s\n", result.DurationString)

	fmt.Println("======================================================================")
}

// printRestoreResult displays restore result
func printRestoreResult(result *backup.RestoreResult) {
	fmt.Println("======================================================================")
	if result.Success {
		if result.DryRun {
			fmt.Println("RESTORE PREVIEW (DRY RUN)")
		} else {
			fmt.Println("RESTORE COMPLETED SUCCESSFULLY")
		}
	} else {
		fmt.Println("RESTORE FAILED")
	}
	fmt.Println("======================================================================")

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
		return
	}

	fmt.Printf("Files Restored:  %d\n", result.FilesRestored)
	fmt.Printf("Duration:        %s\n", result.DurationString)

	if result.OrphansFound > 0 {
		fmt.Printf("\nOrphan Records:\n")
		fmt.Printf("  Found:   %d\n", result.OrphansFound)
		fmt.Printf("  Kept:    %d\n", result.OrphansKept)
		fmt.Printf("  Removed: %d\n", result.OrphansRemoved)
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range result.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	if len(result.TablesRestored) > 0 {
		fmt.Println("\nTables Restored:")
		for _, t := range result.TablesRestored {
			fmt.Printf("  - %s\n", t)
		}
	}

	fmt.Println("======================================================================")
}

// printVerifyResult displays verification result
func printVerifyResult(result *backup.VerifyResult) {
	fmt.Println("======================================================================")
	if result.Valid {
		fmt.Println("BACKUP VERIFICATION PASSED")
	} else {
		fmt.Println("BACKUP VERIFICATION FAILED")
	}
	fmt.Println("======================================================================")

	if result.Manifest != nil {
		fmt.Printf("Mode:            %s\n", result.Manifest.Mode)
		fmt.Printf("Created At:      %s\n", result.Manifest.CreatedAt.Format(time.RFC3339))
		fmt.Printf("SafeShare Ver:   %s\n", result.Manifest.SafeShareVersion)
	}

	fmt.Println("\nChecks:")
	fmt.Printf("  Manifest:      %s\n", boolToStatus(result.ManifestValid))
	fmt.Printf("  Database:      %s\n", boolToStatus(result.DatabaseValid))
	fmt.Printf("  Checksums:     %s\n", boolToStatus(result.ChecksumsValid))
	fmt.Printf("  Files:         %s\n", boolToStatus(result.FilesValid))

	if len(result.MissingFiles) > 0 {
		fmt.Printf("\nMissing Files (%d):\n", len(result.MissingFiles))
		for i, f := range result.MissingFiles {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(result.MissingFiles)-10)
				break
			}
			fmt.Printf("  - %s\n", f)
		}
	}

	if len(result.ChecksumMismatches) > 0 {
		fmt.Printf("\nChecksum Mismatches (%d):\n", len(result.ChecksumMismatches))
		for i, m := range result.ChecksumMismatches {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(result.ChecksumMismatches)-10)
				break
			}
			fmt.Printf("  - %s\n", m.File)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Println("\nErrors:")
		for _, e := range result.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range result.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	fmt.Println("======================================================================")
}

// printBackupList displays list of backups
func printBackupList(backups []backup.BackupInfo) {
	if len(backups) == 0 {
		fmt.Println("No backups found.")
		return
	}

	fmt.Println("======================================================================")
	fmt.Println("AVAILABLE BACKUPS")
	fmt.Println("======================================================================")
	fmt.Printf("%-40s %-10s %-12s %s\n", "NAME", "MODE", "SIZE", "CREATED")
	fmt.Println("----------------------------------------------------------------------")

	for _, b := range backups {
		name := filepath.Base(b.Path)
		if len(name) > 38 {
			name = name[:35] + "..."
		}
		fmt.Printf("%-40s %-10s %-12s %s\n",
			name,
			b.Mode,
			formatBytes(b.TotalSizeBytes),
			b.CreatedAt.Format("2006-01-02 15:04"),
		)
	}

	fmt.Println("======================================================================")
	fmt.Printf("Total: %d backup(s)\n", len(backups))
}

// formatBytes formats byte count as human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// boolToStatus converts bool to status string
func boolToStatus(b bool) string {
	if b {
		return "OK"
	}
	return "FAILED"
}
