package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	// ManifestFilename is the name of the manifest file in backup directories
	ManifestFilename = "manifest.json"

	// DatabaseFilename is the name of the database backup file
	DatabaseFilename = "safeshare.db"

	// UploadsDirname is the name of the uploads directory in full backups
	UploadsDirname = "uploads"
)

// NewManifest creates a new backup manifest with default values
func NewManifest(mode BackupMode, safeShareVersion string) *BackupManifest {
	return &BackupManifest{
		Version:          ManifestVersion,
		CreatedAt:        time.Now().UTC(),
		SafeShareVersion: safeShareVersion,
		Mode:             mode,
		Includes:         getIncludesForMode(mode),
		Stats:            BackupStats{},
		Checksums:        make(map[string]string),
		Encryption:       EncryptionInfo{},
		Warnings:         []string{},
	}
}

// getIncludesForMode returns the BackupIncludes based on backup mode
func getIncludesForMode(mode BackupMode) BackupIncludes {
	switch mode {
	case ModeConfig:
		return BackupIncludes{
			Settings:         true,
			Users:            false,
			FileMetadata:     false,
			Files:            false,
			Webhooks:         true,
			APITokens:        false,
			BlockedIPs:       true,
			AdminCredentials: true,
		}
	case ModeDatabase:
		return BackupIncludes{
			Settings:         true,
			Users:            true,
			FileMetadata:     true,
			Files:            false,
			Webhooks:         true,
			APITokens:        true,
			BlockedIPs:       true,
			AdminCredentials: true,
		}
	case ModeFull:
		return BackupIncludes{
			Settings:         true,
			Users:            true,
			FileMetadata:     true,
			Files:            true,
			Webhooks:         true,
			APITokens:        true,
			BlockedIPs:       true,
			AdminCredentials: true,
		}
	default:
		return BackupIncludes{}
	}
}

// ReadManifest reads and parses a manifest from a backup directory
func ReadManifest(backupDir string) (*BackupManifest, error) {
	manifestPath := filepath.Join(backupDir, ManifestFilename)

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("manifest file not found: %s", manifestPath)
		}
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest BackupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// WriteManifest writes a manifest to a backup directory
func WriteManifest(manifest *BackupManifest, backupDir string) error {
	manifestPath := filepath.Join(backupDir, ManifestFilename)

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, data, BackupFilePerms); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// ValidateManifest checks if a manifest is valid and complete
func ValidateManifest(manifest *BackupManifest) error {
	if manifest == nil {
		return fmt.Errorf("manifest is nil")
	}

	if manifest.Version == "" {
		return fmt.Errorf("manifest version is empty")
	}

	if manifest.CreatedAt.IsZero() {
		return fmt.Errorf("manifest created_at is zero")
	}

	if !manifest.Mode.IsValid() {
		return fmt.Errorf("invalid backup mode: %s", manifest.Mode)
	}

	if manifest.Checksums == nil {
		return fmt.Errorf("manifest checksums map is nil")
	}

	// Database checksum is required for all backup modes (all modes include database backup)
	if _, ok := manifest.Checksums[DatabaseFilename]; !ok {
		return fmt.Errorf("database checksum is missing")
	}

	return nil
}

// ComputeChecksum computes the SHA256 checksum of a file
func ComputeChecksum(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to compute checksum: %w", err)
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeKeyFingerprint computes the SHA256 fingerprint of an encryption key
// This allows verification that the correct key is used without storing the key itself
func ComputeKeyFingerprint(encryptionKey string) string {
	if encryptionKey == "" {
		return ""
	}

	h := sha256.Sum256([]byte(encryptionKey))
	return "sha256:" + hex.EncodeToString(h[:])
}

// VerifyChecksum verifies a file's checksum matches the expected value
func VerifyChecksum(filePath, expectedChecksum string) error {
	actualChecksum, err := ComputeChecksum(filePath)
	if err != nil {
		return fmt.Errorf("failed to compute checksum: %w", err)
	}

	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// GetBackupDirName generates a backup directory name based on timestamp
func GetBackupDirName() string {
	return fmt.Sprintf("backup-%s", time.Now().UTC().Format("2006-01-15T15-04-05"))
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(filePath string) (int64, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// GetDirectorySize calculates the total size of all files in a directory
func GetDirectorySize(dirPath string) (int64, error) {
	var totalSize int64

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	return totalSize, err
}
