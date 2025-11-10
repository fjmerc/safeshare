package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	// SafeShare internal packages
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"

	// External dependencies
	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

// Version information
const (
	ToolVersion = "1.0.0"
	ToolName    = "SafeShare Import Tool"
)

// ImportOptions holds all configuration for an import operation
type ImportOptions struct {
	// Input mode (mutually exclusive)
	SourceFile string
	Directory  string
	Recursive  bool

	// File metadata
	DisplayName  string
	ExpiresHours int
	MaxDownloads int
	Password     string
	UserID       int // Optional user_id for authenticated imports

	// Database and storage
	DBPath      string
	UploadsDir  string
	EncryptKey  string
	PublicURL   string
	UploaderIP  string

	// Behavior flags
	DryRun   bool
	Verify   bool
	NoDelete bool
	Quiet    bool
	JSON     bool

	// Loaded settings
	BlockedExtensions []string
	QuotaLimitGB      int64
}

// ImportResult represents the outcome of a single file import
type ImportResult struct {
	SourcePath       string    `json:"source_path"`
	DisplayName      string    `json:"display_name"`
	OriginalSize     int64     `json:"original_size"`
	EncryptedSize    int64     `json:"encrypted_size"`
	ClaimCode        string    `json:"claim_code"`
	DownloadURL      string    `json:"download_url"`
	ExpiresAt        time.Time `json:"expires_at"`
	EncryptionTime   string    `json:"encryption_time"`
	VerificationTime string    `json:"verification_time,omitempty"`
	Success          bool      `json:"success"`
	Error            string    `json:"error,omitempty"`
	Skipped          bool      `json:"skipped"`
	SkipReason       string    `json:"skip_reason,omitempty"`
}

// BatchSummary represents the overall results of a batch import
type BatchSummary struct {
	TotalFiles       int                `json:"total_files"`
	Successful       int                `json:"successful"`
	Failed           int                `json:"failed"`
	Skipped          int                `json:"skipped"`
	TotalTime        string             `json:"total_time"`
	TotalSize        int64              `json:"total_size"`
	TotalEncrypted   int64              `json:"total_encrypted"`
	Results          []*ImportResult    `json:"results"`
	FailedFiles      []string           `json:"failed_files,omitempty"`
}

func main() {
	// Parse command-line flags
	opts := &ImportOptions{}

	// Input mode
	flag.StringVar(&opts.SourceFile, "source", "", "Path to source file (single file mode)")
	flag.StringVar(&opts.Directory, "directory", "", "Path to directory (batch mode)")
	flag.BoolVar(&opts.Recursive, "recursive", false, "Recursively scan subdirectories in batch mode")

	// File metadata
	flag.StringVar(&opts.DisplayName, "filename", "", "Display filename (defaults to source filename)")
	flag.IntVar(&opts.ExpiresHours, "expires", 168, "Expiration time in hours (default: 168 = 7 days)")
	flag.IntVar(&opts.MaxDownloads, "maxdownloads", 0, "Maximum downloads (0 = unlimited)")
	flag.StringVar(&opts.Password, "password", "", "Optional password protection")
	flag.IntVar(&opts.UserID, "user-id", 0, "Optional user_id for authenticated imports (sets file ownership)")

	// Database and storage
	flag.StringVar(&opts.DBPath, "db", "", "Path to SafeShare database (required)")
	flag.StringVar(&opts.UploadsDir, "uploads", "", "Path to SafeShare uploads directory (required)")
	flag.StringVar(&opts.EncryptKey, "enckey", "", "Encryption key (64 hex chars, required)")
	flag.StringVar(&opts.PublicURL, "public-url", "https://share.example.com", "Public URL for download links")
	flag.StringVar(&opts.UploaderIP, "ip", "import-tool", "Uploader IP to record")

	// Behavior flags
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Preview only, no changes")
	flag.BoolVar(&opts.Verify, "verify", false, "Verify file integrity after encryption (hash check)")
	flag.BoolVar(&opts.NoDelete, "no-delete", false, "Preserve source files (copy instead of move)")
	flag.BoolVar(&opts.Quiet, "quiet", false, "Minimal output for scripting")
	flag.BoolVar(&opts.JSON, "json", false, "JSON output format")

	// Version flag
	version := flag.Bool("version", false, "Show version information")

	flag.Parse()

	// Show version and exit
	if *version {
		fmt.Printf("%s v%s\n", ToolName, ToolVersion)
		os.Exit(0)
	}

	// Validate required parameters
	if err := validateOptions(opts); err != nil {
		log.Fatalf("Error: %v\n\nUse -h for usage information.", err)
	}

	// Load settings from database (blocked extensions, quota)
	if err := loadSettings(opts); err != nil {
		log.Fatalf("Error loading settings: %v", err)
	}

	// Determine mode and execute
	if opts.SourceFile != "" {
		// Single file mode
		result := importSingleFile(opts)
		if opts.JSON {
			printJSON(result)
		} else if !opts.Quiet {
			printResult(result)
		}
		if !result.Success {
			os.Exit(1)
		}
	} else {
		// Batch mode
		summary := importDirectory(opts)
		if opts.JSON {
			printJSON(summary)
		} else if !opts.Quiet {
			printSummary(summary)
		}
		if summary.Failed > 0 {
			os.Exit(1)
		}
	}
}

// validateOptions validates command-line options
func validateOptions(opts *ImportOptions) error {
	// Validate input mode (exactly one must be set)
	if opts.SourceFile == "" && opts.Directory == "" {
		return fmt.Errorf("either -source or -directory must be specified")
	}
	if opts.SourceFile != "" && opts.Directory != "" {
		return fmt.Errorf("cannot specify both -source and -directory")
	}

	// Validate required parameters
	if opts.DBPath == "" {
		return fmt.Errorf("-db flag is required")
	}
	if opts.UploadsDir == "" {
		return fmt.Errorf("-uploads flag is required")
	}
	if opts.EncryptKey == "" {
		return fmt.Errorf("-enckey flag is required")
	}

	// Validate encryption key format
	if len(opts.EncryptKey) != 64 {
		return fmt.Errorf("encryption key must be exactly 64 hexadecimal characters, got %d", len(opts.EncryptKey))
	}
	if _, err := hex.DecodeString(opts.EncryptKey); err != nil {
		return fmt.Errorf("encryption key must be valid hexadecimal: %w", err)
	}

	// Validate source file exists (single file mode)
	if opts.SourceFile != "" {
		if _, err := os.Stat(opts.SourceFile); err != nil {
			return fmt.Errorf("cannot access source file: %w", err)
		}
	}

	// Validate directory exists (batch mode)
	if opts.Directory != "" {
		info, err := os.Stat(opts.Directory)
		if err != nil {
			return fmt.Errorf("cannot access directory: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("path is not a directory: %s", opts.Directory)
		}
	}

	// Validate database exists and is accessible
	if _, err := os.Stat(opts.DBPath); err != nil {
		return fmt.Errorf("cannot access database: %w", err)
	}

	// Validate uploads directory exists and is writable
	if info, err := os.Stat(opts.UploadsDir); err != nil {
		return fmt.Errorf("cannot access uploads directory: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("uploads path is not a directory: %s", opts.UploadsDir)
	}

	return nil
}

// loadSettings loads blocked extensions and quota from database
func loadSettings(opts *ImportOptions) error {
	db, err := sql.Open("sqlite", opts.DBPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer db.Close()

	// Load settings from database
	settings, err := database.GetSettings(db)
	if err != nil {
		return fmt.Errorf("failed to load settings: %w", err)
	}

	// Apply settings if they exist, otherwise use defaults
	if settings != nil {
		opts.BlockedExtensions = settings.BlockedExtensions
		opts.QuotaLimitGB = settings.QuotaLimitGB
	} else {
		// No settings in database, use environment variable defaults
		// These would typically be loaded from config, but we'll use safe defaults
		opts.BlockedExtensions = []string{
			".exe", ".bat", ".cmd", ".sh", ".ps1", ".dll", ".so",
			".msi", ".scr", ".vbs", ".jar", ".com", ".app",
			".deb", ".rpm",
		}
		opts.QuotaLimitGB = 0 // Unlimited by default
	}

	return nil
}

// parseBlockedExtensions converts comma-separated string to slice
func parseBlockedExtensions(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		ext := strings.TrimSpace(p)
		if ext != "" {
			// Ensure extension starts with dot
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			result = append(result, strings.ToLower(ext))
		}
	}
	return result
}

// importSingleFile imports a single file
func importSingleFile(opts *ImportOptions) *ImportResult {
	sourceInfo, err := os.Stat(opts.SourceFile)
	if err != nil {
		return &ImportResult{
			SourcePath: opts.SourceFile,
			Success:    false,
			Error:      fmt.Sprintf("cannot access source file: %v", err),
		}
	}

	// Use source filename if display name not provided
	displayName := opts.DisplayName
	if displayName == "" {
		displayName = filepath.Base(opts.SourceFile)
	}

	// Check if file extension is blocked
	if err := validateFileExtension(displayName, opts.BlockedExtensions); err != nil {
		return &ImportResult{
			SourcePath:  opts.SourceFile,
			DisplayName: displayName,
			Skipped:     true,
			SkipReason:  err.Error(),
		}
	}

	// Check quota
	if opts.QuotaLimitGB > 0 {
		db, err := sql.Open("sqlite", opts.DBPath)
		if err != nil {
			return &ImportResult{
				SourcePath: opts.SourceFile,
				Success:    false,
				Error:      fmt.Sprintf("failed to open database: %v", err),
			}
		}
		defer db.Close()

		if err := checkQuotaAvailable(db, sourceInfo.Size(), opts.QuotaLimitGB); err != nil {
			return &ImportResult{
				SourcePath:  opts.SourceFile,
				DisplayName: displayName,
				Skipped:     true,
				SkipReason:  err.Error(),
			}
		}
	}

	// Check disk space
	if err := validateDiskSpace(opts.UploadsDir, sourceInfo.Size()); err != nil {
		return &ImportResult{
			SourcePath:  opts.SourceFile,
			DisplayName: displayName,
			Success:     false,
			Error:       err.Error(),
		}
	}

	// Dry run - just report what would happen
	if opts.DryRun {
		return &ImportResult{
			SourcePath:   opts.SourceFile,
			DisplayName:  displayName,
			OriginalSize: sourceInfo.Size(),
			Success:      true,
		}
	}

	// Perform actual import
	return encryptAndRegisterFile(opts.SourceFile, displayName, sourceInfo.Size(), opts)
}

// importDirectory imports all files in a directory
func importDirectory(opts *ImportOptions) *BatchSummary {
	startTime := time.Now()
	summary := &BatchSummary{
		Results: []*ImportResult{},
	}

	// Collect all files to import
	filesToImport := []string{}

	walkFn := func(path string, info os.FileInfo, err error) error {
		// Skip errors
		if err != nil {
			log.Printf("Warning: Cannot access %s: %v", path, err)
			return nil
		}

		// Skip directories
		if info.IsDir() {
			// If not recursive, skip subdirectories
			if !opts.Recursive && path != opts.Directory {
				return filepath.SkipDir
			}
			return nil
		}

		filesToImport = append(filesToImport, path)
		return nil
	}

	// Walk directory
	if err := filepath.Walk(opts.Directory, walkFn); err != nil {
		log.Printf("Error walking directory: %v", err)
	}

	summary.TotalFiles = len(filesToImport)

	// Dry run - preview what would be imported
	if opts.DryRun {
		return previewImport(filesToImport, opts)
	}

	// Import each file
	for i, path := range filesToImport {
		if !opts.Quiet && !opts.JSON {
			fmt.Printf("\n[%d/%d] %s\n", i+1, len(filesToImport), filepath.Base(path))
		}

		displayName := filepath.Base(path)

		// Get file info
		info, err := os.Stat(path)
		if err != nil {
			result := &ImportResult{
				SourcePath: path,
				Success:    false,
				Error:      fmt.Sprintf("cannot stat file: %v", err),
			}
			summary.Results = append(summary.Results, result)
			summary.Failed++
			continue
		}

		// Check extension
		if err := validateFileExtension(displayName, opts.BlockedExtensions); err != nil {
			result := &ImportResult{
				SourcePath:  path,
				DisplayName: displayName,
				Skipped:     true,
				SkipReason:  err.Error(),
			}
			summary.Results = append(summary.Results, result)
			summary.Skipped++
			if !opts.Quiet && !opts.JSON {
				fmt.Printf("  └─ SKIPPED: %s\n", err.Error())
			}
			continue
		}

		// Check quota
		if opts.QuotaLimitGB > 0 {
			db, err := sql.Open("sqlite", opts.DBPath)
			if err != nil {
				result := &ImportResult{
					SourcePath: path,
					Success:    false,
					Error:      fmt.Sprintf("failed to open database: %v", err),
				}
				summary.Results = append(summary.Results, result)
				summary.Failed++
				continue
			}

			if err := checkQuotaAvailable(db, info.Size(), opts.QuotaLimitGB); err != nil {
				db.Close()
				result := &ImportResult{
					SourcePath:  path,
					DisplayName: displayName,
					Skipped:     true,
					SkipReason:  err.Error(),
				}
				summary.Results = append(summary.Results, result)
				summary.Skipped++
				if !opts.Quiet && !opts.JSON {
					fmt.Printf("  └─ SKIPPED: %s\n", err.Error())
				}
				continue
			}
			db.Close()
		}

		// Import file
		result := encryptAndRegisterFile(path, displayName, info.Size(), opts)
		summary.Results = append(summary.Results, result)

		if result.Success {
			summary.Successful++
			summary.TotalSize += result.OriginalSize
			summary.TotalEncrypted += result.EncryptedSize
			if !opts.Quiet && !opts.JSON {
				fmt.Printf("  ├─ Claim code: %s\n", result.ClaimCode)
				fmt.Printf("  └─ Download: %s\n", result.DownloadURL)
			}
		} else {
			summary.Failed++
			summary.FailedFiles = append(summary.FailedFiles, fmt.Sprintf("%s: %s", path, result.Error))
			if !opts.Quiet && !opts.JSON {
				fmt.Printf("  └─ FAILED: %s\n", result.Error)
			}
		}
	}

	summary.TotalTime = time.Since(startTime).String()
	return summary
}

// encryptAndRegisterFile performs the core encryption and database registration
func encryptAndRegisterFile(sourcePath, displayName string, originalSize int64, opts *ImportOptions) *ImportResult {
	result := &ImportResult{
		SourcePath:   sourcePath,
		DisplayName:  displayName,
		OriginalSize: originalSize,
	}

	// Open database
	db, err := sql.Open("sqlite", opts.DBPath)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open database: %v", err)
		return result
	}
	defer db.Close()

	// Generate UUID for stored filename
	storedFilename := uuid.New().String()
	destPath := filepath.Join(opts.UploadsDir, storedFilename)

	// Encrypt the file
	if !opts.Quiet && !opts.JSON {
		fmt.Printf("  ├─ Encrypting... ")
	}
	startTime := time.Now()

	err = utils.EncryptFileStreaming(sourcePath, destPath, opts.EncryptKey)
	if err != nil {
		result.Error = fmt.Sprintf("failed to encrypt file: %v", err)
		return result
	}

	encryptionTime := time.Since(startTime)
	result.EncryptionTime = encryptionTime.String()
	if !opts.Quiet && !opts.JSON {
		fmt.Printf("✓ (%s)\n", encryptionTime)
	}

	// Verify if requested
	if opts.Verify {
		if !opts.Quiet && !opts.JSON {
			fmt.Printf("  ├─ Verifying... ")
		}
		startVerify := time.Now()

		if err := verifyEncryptedFile(sourcePath, destPath, opts.EncryptKey); err != nil {
			os.Remove(destPath) // Cleanup
			result.Error = fmt.Sprintf("verification failed: %v", err)
			return result
		}

		verifyTime := time.Since(startVerify)
		result.VerificationTime = verifyTime.String()
		if !opts.Quiet && !opts.JSON {
			fmt.Printf("✓ (%s)\n", verifyTime)
		}
	}

	// Get encrypted file size
	encryptedInfo, err := os.Stat(destPath)
	if err != nil {
		os.Remove(destPath)
		result.Error = fmt.Sprintf("failed to stat encrypted file: %v", err)
		return result
	}
	result.EncryptedSize = encryptedInfo.Size()

	// Detect MIME type
	mtype, err := mimetype.DetectFile(sourcePath)
	if err != nil {
		log.Printf("Warning: Failed to detect MIME type: %v", err)
		mtype = &mimetype.MIME{}
	}
	mimeType := mtype.String()
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// Generate claim code
	claimCode, err := utils.GenerateClaimCode()
	if err != nil {
		os.Remove(destPath)
		result.Error = fmt.Sprintf("failed to generate claim code: %v", err)
		return result
	}

	// Calculate expiration
	expiresAt := time.Now().Add(time.Duration(opts.ExpiresHours) * time.Hour)
	result.ExpiresAt = expiresAt

	// Create file record
	fileRecord := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: displayName,
		StoredFilename:   storedFilename,
		FileSize:         encryptedInfo.Size(),
		MimeType:         mimeType,
		ExpiresAt:        expiresAt,
		UploaderIP:       opts.UploaderIP,
	}

	// Set optional fields
	if opts.MaxDownloads > 0 {
		fileRecord.MaxDownloads = &opts.MaxDownloads
	}
	if opts.UserID > 0 {
		fileRecord.UserID = &opts.UserID
	}
	if opts.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(opts.Password), bcrypt.DefaultCost)
		if err != nil {
			os.Remove(destPath)
			result.Error = fmt.Sprintf("failed to hash password: %v", err)
			return result
		}
		fileRecord.PasswordHash = string(hashedPassword)
	}

	// Insert into database
	if err := database.CreateFile(db, fileRecord); err != nil {
		os.Remove(destPath)
		result.Error = fmt.Sprintf("failed to create database record: %v", err)
		return result
	}

	// Delete source file unless --no-delete
	if !opts.NoDelete {
		if err := os.Remove(sourcePath); err != nil {
			log.Printf("Warning: Failed to delete source file %s: %v", sourcePath, err)
		}
	}

	// Build download URL
	result.ClaimCode = claimCode
	result.DownloadURL = fmt.Sprintf("%s/api/claim/%s", opts.PublicURL, claimCode)
	result.Success = true

	return result
}

// verifyEncryptedFile verifies encrypted file integrity by decrypting and comparing hashes
func verifyEncryptedFile(sourcePath, encryptedPath, encryptionKey string) error {
	// Calculate hash of original file
	originalHash, err := hashFile(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to hash original file: %w", err)
	}

	// Create temp file for decryption
	tempDecrypted := filepath.Join(os.TempDir(), uuid.New().String())
	defer os.Remove(tempDecrypted)

	// Decrypt encrypted file
	if err := utils.DecryptFileStreaming(encryptedPath, tempDecrypted, encryptionKey); err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	// Calculate hash of decrypted file
	decryptedHash, err := hashFile(tempDecrypted)
	if err != nil {
		return fmt.Errorf("failed to hash decrypted file: %w", err)
	}

	// Compare hashes
	if originalHash != decryptedHash {
		return fmt.Errorf("hash mismatch (original: %s, decrypted: %s)", originalHash[:16], decryptedHash[:16])
	}

	return nil
}

// hashFile calculates SHA256 hash of a file
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// validateFileExtension checks if file extension is blocked
func validateFileExtension(filename string, blockedExts []string) error {
	lowerFilename := strings.ToLower(filename)

	for _, ext := range blockedExts {
		// Check simple extension
		if strings.HasSuffix(lowerFilename, ext) {
			return fmt.Errorf("blocked extension: %s", ext)
		}

		// Check double extension (e.g., .tar.exe)
		parts := strings.Split(lowerFilename, ".")
		if len(parts) >= 2 {
			lastTwo := "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
			if strings.HasSuffix(lastTwo, ext) {
				return fmt.Errorf("blocked extension: %s", ext)
			}
		}
	}

	return nil
}

// checkQuotaAvailable checks if quota allows the file
func checkQuotaAvailable(db *sql.DB, fileSize int64, quotaGB int64) error {
	// Get current usage
	var currentUsage int64
	err := db.QueryRow("SELECT COALESCE(SUM(file_size), 0) FROM files").Scan(&currentUsage)
	if err != nil {
		return fmt.Errorf("failed to query current usage: %w", err)
	}

	// Calculate quota in bytes
	quotaBytes := quotaGB * 1024 * 1024 * 1024

	// Check if file would exceed quota
	if currentUsage+fileSize > quotaBytes {
		return fmt.Errorf("quota exceeded (current: %.2f GB, file: %.2f GB, limit: %d GB)",
			float64(currentUsage)/1024/1024/1024,
			float64(fileSize)/1024/1024/1024,
			quotaGB)
	}

	return nil
}

// validateDiskSpace checks if sufficient disk space is available
func validateDiskSpace(uploadsDir string, fileSize int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(uploadsDir, &stat); err != nil {
		return fmt.Errorf("failed to check disk space: %w", err)
	}

	// Calculate available space
	availableBytes := stat.Bavail * uint64(stat.Bsize)

	// Require at least 1GB free or file size * 1.1 (encryption overhead)
	requiredBytes := uint64(float64(fileSize) * 1.1)
	minFreeSpace := uint64(1024 * 1024 * 1024) // 1GB

	if requiredBytes > minFreeSpace {
		minFreeSpace = requiredBytes
	}

	if availableBytes < minFreeSpace {
		return fmt.Errorf("insufficient disk space (available: %.2f GB, required: %.2f GB)",
			float64(availableBytes)/1024/1024/1024,
			float64(minFreeSpace)/1024/1024/1024)
	}

	return nil
}

// previewImport shows what would be imported in dry-run mode
func previewImport(files []string, opts *ImportOptions) *BatchSummary {
	summary := &BatchSummary{
		TotalFiles: len(files),
		Results:    []*ImportResult{},
	}

	fmt.Println("DRY RUN MODE - No changes will be made\n")
	fmt.Println("Files to be imported:")

	var totalSize int64

	for i, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Printf("  %d. %s\n", i+1, filepath.Base(path))
			fmt.Printf("     └─ ERROR: %v\n", err)
			summary.Failed++
			continue
		}

		displayName := filepath.Base(path)
		fmt.Printf("\n  %d. %s (%.2f GB)\n", i+1, displayName, float64(info.Size())/1024/1024/1024)

		// Check extension
		if err := validateFileExtension(displayName, opts.BlockedExtensions); err != nil {
			fmt.Printf("     └─ WILL SKIP: %s\n", err.Error())
			summary.Skipped++
			continue
		}

		fmt.Printf("     ├─ Display name: %s\n", displayName)
		fmt.Printf("     ├─ Size: %.2f GB\n", float64(info.Size())/1024/1024/1024)
		fmt.Printf("     ├─ Expires: %s\n", time.Now().Add(time.Duration(opts.ExpiresHours)*time.Hour).Format(time.RFC3339))
		if opts.MaxDownloads > 0 {
			fmt.Printf("     ├─ Max downloads: %d\n", opts.MaxDownloads)
		} else {
			fmt.Printf("     ├─ Max downloads: unlimited\n")
		}
		fmt.Printf("     ├─ Password protected: %v\n", opts.Password != "")
		fmt.Printf("     └─ Will delete source: %v\n", !opts.NoDelete)

		totalSize += info.Size()
		summary.Successful++
	}

	fmt.Printf("\n\nSUMMARY:\n")
	fmt.Printf("  Total files: %d\n", len(files))
	fmt.Printf("  Will import: %d\n", summary.Successful)
	fmt.Printf("  Will skip: %d\n", summary.Skipped)
	fmt.Printf("  Errors: %d\n", summary.Failed)
	fmt.Printf("  Total size: %.2f GB\n", float64(totalSize)/1024/1024/1024)

	if opts.Verify {
		fmt.Printf("  Verification: enabled (will double processing time)\n")
	}

	fmt.Printf("\nRun without --dry-run to perform the import.\n")

	return summary
}

// printResult prints a single import result
func printResult(result *ImportResult) {
	fmt.Println("\n======================================================================")
	if result.Success {
		fmt.Println("FILE IMPORT SUCCESSFUL")
	} else if result.Skipped {
		fmt.Println("FILE IMPORT SKIPPED")
	} else {
		fmt.Println("FILE IMPORT FAILED")
	}
	fmt.Println("======================================================================")
	fmt.Printf("Filename:        %s\n", result.DisplayName)
	fmt.Printf("Original Size:   %.2f GB\n", float64(result.OriginalSize)/1024/1024/1024)

	if result.Success {
		fmt.Printf("Encrypted Size:  %.2f GB\n", float64(result.EncryptedSize)/1024/1024/1024)
		fmt.Printf("Claim Code:      %s\n", result.ClaimCode)
		fmt.Printf("Download URL:    %s\n", result.DownloadURL)
		fmt.Printf("Expires At:      %s\n", result.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Encryption Time: %s\n", result.EncryptionTime)
		if result.VerificationTime != "" {
			fmt.Printf("Verification Time: %s\n", result.VerificationTime)
		}
	} else if result.Skipped {
		fmt.Printf("Reason:          %s\n", result.SkipReason)
	} else {
		fmt.Printf("Error:           %s\n", result.Error)
	}
	fmt.Println("======================================================================")
}

// printSummary prints batch import summary
func printSummary(summary *BatchSummary) {
	fmt.Println("\n======================================================================")
	fmt.Println("BATCH IMPORT SUMMARY")
	fmt.Println("======================================================================")
	fmt.Printf("Total files processed: %d\n", summary.TotalFiles)
	fmt.Printf("Successful:           %d\n", summary.Successful)
	fmt.Printf("Skipped:              %d\n", summary.Skipped)
	fmt.Printf("Failed:               %d\n", summary.Failed)
	fmt.Printf("Total time:           %s\n", summary.TotalTime)

	if summary.Successful > 0 {
		fmt.Printf("Total size:           %.2f GB\n", float64(summary.TotalSize)/1024/1024/1024)
		fmt.Printf("Total encrypted:      %.2f GB\n", float64(summary.TotalEncrypted)/1024/1024/1024)
	}

	if len(summary.FailedFiles) > 0 {
		fmt.Println("\nFailed files:")
		for _, f := range summary.FailedFiles {
			fmt.Printf("  - %s\n", f)
		}
	}
	fmt.Println("======================================================================")
}

// printJSON prints result as JSON
func printJSON(v interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(v)
}
