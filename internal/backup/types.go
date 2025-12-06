// Package backup provides functionality for creating and restoring SafeShare backups.
//
// The backup package supports three backup modes:
//   - config: Settings, webhooks, blocked IPs, admin credentials only
//   - database: Full database without uploaded files
//   - full: Database + all uploaded files
//
// Backups are created as directory structures with a manifest.json file
// that contains metadata, checksums, and information about what's included.
package backup

import (
	"time"
)

// BackupMode defines the type of backup to create
type BackupMode string

const (
	// ModeConfig backs up only configuration: settings, webhooks, blocked IPs, admin credentials
	ModeConfig BackupMode = "config"

	// ModeDatabase backs up the full database without uploaded files
	ModeDatabase BackupMode = "database"

	// ModeFull backs up the database and all uploaded files
	ModeFull BackupMode = "full"
)

// String returns the string representation of BackupMode
func (m BackupMode) String() string {
	return string(m)
}

// IsValid returns true if the backup mode is valid
func (m BackupMode) IsValid() bool {
	switch m {
	case ModeConfig, ModeDatabase, ModeFull:
		return true
	default:
		return false
	}
}

// OrphanHandling defines how to handle orphaned file records during restore
type OrphanHandling string

const (
	// OrphanKeep keeps orphaned file records (metadata preserved, files not recoverable)
	OrphanKeep OrphanHandling = "keep"

	// OrphanRemove removes orphaned file records from the database
	OrphanRemove OrphanHandling = "remove"

	// OrphanPrompt prompts the user for each orphaned record (interactive mode only)
	OrphanPrompt OrphanHandling = "prompt"
)

// String returns the string representation of OrphanHandling
func (o OrphanHandling) String() string {
	return string(o)
}

// IsValid returns true if the orphan handling mode is valid
func (o OrphanHandling) IsValid() bool {
	switch o {
	case OrphanKeep, OrphanRemove, OrphanPrompt:
		return true
	default:
		return false
	}
}

// ManifestVersion is the current backup manifest format version
const ManifestVersion = "1.0"

// BackupManifest contains metadata about a backup
type BackupManifest struct {
	// Version of the manifest format
	Version string `json:"version"`

	// CreatedAt is when the backup was created
	CreatedAt time.Time `json:"created_at"`

	// SafeShareVersion is the version of SafeShare that created this backup
	SafeShareVersion string `json:"safeshare_version"`

	// Mode indicates what type of backup this is
	Mode BackupMode `json:"mode"`

	// Includes describes what data is included in this backup
	Includes BackupIncludes `json:"includes"`

	// Stats contains counts and sizes of backed up data
	Stats BackupStats `json:"stats"`

	// Checksums contains SHA256 checksums of backup files
	Checksums map[string]string `json:"checksums"`

	// Encryption contains information about encryption state
	Encryption EncryptionInfo `json:"encryption"`

	// Warnings contains any warnings generated during backup
	Warnings []string `json:"warnings,omitempty"`

	// SourceDBPath is the original database path (informational only)
	SourceDBPath string `json:"source_db_path,omitempty"`

	// SourceUploadsDir is the original uploads directory (informational only)
	SourceUploadsDir string `json:"source_uploads_dir,omitempty"`
}

// BackupIncludes describes what data types are included in the backup
type BackupIncludes struct {
	// Settings indicates if runtime settings are included
	Settings bool `json:"settings"`

	// Users indicates if user accounts are included
	Users bool `json:"users"`

	// FileMetadata indicates if file records (metadata) are included
	FileMetadata bool `json:"file_metadata"`

	// Files indicates if actual uploaded files are included
	Files bool `json:"files"`

	// Webhooks indicates if webhook configurations are included
	Webhooks bool `json:"webhooks"`

	// APITokens indicates if API tokens are included
	APITokens bool `json:"api_tokens"`

	// BlockedIPs indicates if IP blocklist is included
	BlockedIPs bool `json:"blocked_ips"`

	// AdminCredentials indicates if admin credentials are included
	AdminCredentials bool `json:"admin_credentials"`
}

// BackupStats contains statistics about the backup
type BackupStats struct {
	// UsersCount is the number of user accounts
	UsersCount int `json:"users_count"`

	// FileRecordsCount is the number of file metadata records
	FileRecordsCount int `json:"file_records_count"`

	// FilesBackedUp is the number of actual files backed up (0 if mode != full)
	FilesBackedUp int `json:"files_backed_up"`

	// WebhooksCount is the number of webhook configurations
	WebhooksCount int `json:"webhooks_count"`

	// APITokensCount is the number of API tokens
	APITokensCount int `json:"api_tokens_count"`

	// BlockedIPsCount is the number of blocked IP entries
	BlockedIPsCount int `json:"blocked_ips_count"`

	// TotalSizeBytes is the total size of the backup in bytes
	TotalSizeBytes int64 `json:"total_size_bytes"`

	// DatabaseSizeBytes is the size of the database backup
	DatabaseSizeBytes int64 `json:"database_size_bytes"`

	// FilesSizeBytes is the total size of backed up files (0 if mode != full)
	FilesSizeBytes int64 `json:"files_size_bytes"`
}

// EncryptionInfo contains information about the encryption state
type EncryptionInfo struct {
	// Enabled indicates if encryption was enabled when backup was created
	Enabled bool `json:"enabled"`

	// KeyFingerprint is the SHA256 hash of the encryption key (for verification)
	// This allows verification that the correct key is used during restore
	// without storing the actual key in the backup
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

// CreateOptions contains options for creating a backup
type CreateOptions struct {
	// Mode is the type of backup to create
	Mode BackupMode

	// DBPath is the path to the SQLite database
	DBPath string

	// UploadsDir is the path to the uploads directory (required for full mode)
	UploadsDir string

	// OutputDir is the directory where the backup will be created
	OutputDir string

	// EncryptionKey is the 64-character hex encryption key (for fingerprint)
	EncryptionKey string

	// SafeShareVersion is the application version string
	SafeShareVersion string

	// ProgressCallback is called with progress updates during backup
	// Parameters: current step, total steps, description
	ProgressCallback func(current, total int, description string)
}

// RestoreOptions contains options for restoring from a backup
type RestoreOptions struct {
	// InputDir is the path to the backup directory
	InputDir string

	// DBPath is the path where the database should be restored
	DBPath string

	// UploadsDir is the path where files should be restored (for full backups)
	UploadsDir string

	// HandleOrphans defines how to handle orphaned file records
	HandleOrphans OrphanHandling

	// DryRun previews the restore without making changes
	DryRun bool

	// Force overwrites existing data without confirmation
	Force bool

	// EncryptionKey is used to verify against the key fingerprint
	EncryptionKey string

	// OrphanCallback is called for each orphan when HandleOrphans is OrphanPrompt
	// Returns true to keep the record, false to remove it
	OrphanCallback func(claimCode, filename string, fileSize int64) bool

	// ProgressCallback is called with progress updates during restore
	// Parameters: current step, total steps, description
	ProgressCallback func(current, total int, description string)
}

// BackupResult contains the result of a backup operation
type BackupResult struct {
	// Success indicates if the backup completed successfully
	Success bool `json:"success"`

	// BackupPath is the path to the created backup directory
	BackupPath string `json:"backup_path,omitempty"`

	// Manifest is the backup manifest (included on success)
	Manifest *BackupManifest `json:"manifest,omitempty"`

	// Error is the error message if backup failed
	Error string `json:"error,omitempty"`

	// Duration is how long the backup took
	Duration time.Duration `json:"duration"`

	// DurationString is a human-readable duration
	DurationString string `json:"duration_string"`
}

// RestoreResult contains the result of a restore operation
type RestoreResult struct {
	// Success indicates if the restore completed successfully
	Success bool `json:"success"`

	// DryRun indicates if this was a dry run
	DryRun bool `json:"dry_run"`

	// Error is the error message if restore failed
	Error string `json:"error,omitempty"`

	// Warnings contains any warnings generated during restore
	Warnings []string `json:"warnings,omitempty"`

	// TablesRestored lists the database tables that were restored
	TablesRestored []string `json:"tables_restored,omitempty"`

	// FilesRestored is the count of files restored (for full backups)
	FilesRestored int `json:"files_restored"`

	// OrphansFound is the count of orphaned file records found
	OrphansFound int `json:"orphans_found"`

	// OrphansRemoved is the count of orphaned records that were removed
	OrphansRemoved int `json:"orphans_removed"`

	// OrphansKept is the count of orphaned records that were kept
	OrphansKept int `json:"orphans_kept"`

	// Duration is how long the restore took
	Duration time.Duration `json:"duration"`

	// DurationString is a human-readable duration
	DurationString string `json:"duration_string"`
}

// VerifyResult contains the result of a backup verification
type VerifyResult struct {
	// Valid indicates if the backup is valid and complete
	Valid bool `json:"valid"`

	// ManifestValid indicates if the manifest is readable and valid
	ManifestValid bool `json:"manifest_valid"`

	// DatabaseValid indicates if the database file is present and valid
	DatabaseValid bool `json:"database_valid"`

	// ChecksumsValid indicates if all checksums match
	ChecksumsValid bool `json:"checksums_valid"`

	// FilesValid indicates if all expected files are present (for full backups)
	FilesValid bool `json:"files_valid"`

	// Errors contains any validation errors found
	Errors []string `json:"errors,omitempty"`

	// Warnings contains any validation warnings
	Warnings []string `json:"warnings,omitempty"`

	// Manifest is the parsed manifest (if readable)
	Manifest *BackupManifest `json:"manifest,omitempty"`

	// MissingFiles lists files referenced in manifest but not found
	MissingFiles []string `json:"missing_files,omitempty"`

	// ChecksumMismatches lists files with checksum mismatches
	ChecksumMismatches []ChecksumMismatch `json:"checksum_mismatches,omitempty"`
}

// ChecksumMismatch represents a file with a checksum mismatch
type ChecksumMismatch struct {
	// File is the filename
	File string `json:"file"`

	// Expected is the expected checksum from manifest
	Expected string `json:"expected"`

	// Actual is the actual computed checksum
	Actual string `json:"actual"`
}

// BackupInfo contains summary information about a backup (for listing)
type BackupInfo struct {
	// Path is the path to the backup directory
	Path string `json:"path"`

	// Name is the directory name
	Name string `json:"name"`

	// CreatedAt is when the backup was created
	CreatedAt time.Time `json:"created_at"`

	// Mode is the backup mode
	Mode BackupMode `json:"mode"`

	// SafeShareVersion is the SafeShare version that created the backup
	SafeShareVersion string `json:"safeshare_version"`

	// TotalSizeBytes is the total backup size
	TotalSizeBytes int64 `json:"total_size_bytes"`

	// FileRecordsCount is the number of file records
	FileRecordsCount int `json:"file_records_count"`

	// FilesBackedUp is the number of files (for full backups)
	FilesBackedUp int `json:"files_backed_up"`
}

// JobStatus represents the status of an async backup/restore job
type JobStatus string

const (
	// JobStatusPending indicates the job is queued but not started
	JobStatusPending JobStatus = "pending"

	// JobStatusRunning indicates the job is currently executing
	JobStatusRunning JobStatus = "running"

	// JobStatusCompleted indicates the job completed successfully
	JobStatusCompleted JobStatus = "completed"

	// JobStatusFailed indicates the job failed
	JobStatusFailed JobStatus = "failed"
)

// BackupJob represents an async backup or restore job
type BackupJob struct {
	// ID is the unique job identifier
	ID string `json:"id"`

	// Type is either "backup" or "restore"
	Type string `json:"type"`

	// Mode is the backup mode
	Mode BackupMode `json:"mode"`

	// Status is the current job status
	Status JobStatus `json:"status"`

	// Progress is the percentage complete (0-100)
	Progress int `json:"progress"`

	// OutputPath is the path to the backup (for completed backups)
	OutputPath string `json:"output_path,omitempty"`

	// Error is the error message (for failed jobs)
	Error string `json:"error,omitempty"`

	// StartedAt is when the job started
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the job completed (nil if still running)
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ExcludedTables lists tables that should NOT be backed up
var ExcludedTables = []string{
	"user_sessions",   // Sessions should not be restored
	"admin_sessions",  // Admin sessions should not be restored
	"partial_uploads", // Temporary chunked upload data
}

// ConfigTables lists tables included in config-only backups
var ConfigTables = []string{
	"settings",
	"admin_credentials",
	"blocked_ips",
	"webhook_configs",
}

// FullDatabaseTables lists all tables included in database/full backups
var FullDatabaseTables = []string{
	"files",
	"users",
	"settings",
	"admin_credentials",
	"blocked_ips",
	"webhook_configs",
	"api_tokens",
	"webhook_deliveries",
}
