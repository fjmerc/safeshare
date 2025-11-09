package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const (
	// MinimumFreeSpace is the minimum free disk space required (in bytes)
	MinimumFreeSpace = 1 * 1024 * 1024 * 1024 // 1GB

	// MaximumDiskUsagePercent is the maximum allowed disk usage percentage
	MaximumDiskUsagePercent = 80 // 80%
)

// DiskSpaceInfo contains information about disk space
type DiskSpaceInfo struct {
	TotalBytes     uint64
	FreeBytes      uint64
	AvailableBytes uint64
	UsedBytes      uint64
	UsedPercent    float64
}

// GetDiskSpace returns disk space information for a given path
func GetDiskSpace(path string) (*DiskSpaceInfo, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return nil, fmt.Errorf("failed to get disk space: %w", err)
	}

	// Calculate disk space metrics
	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freeBytes := stat.Bfree * uint64(stat.Bsize)
	availableBytes := stat.Bavail * uint64(stat.Bsize) // Available to non-root users
	usedBytes := totalBytes - freeBytes
	usedPercent := float64(usedBytes) / float64(totalBytes) * 100

	return &DiskSpaceInfo{
		TotalBytes:     totalBytes,
		FreeBytes:      freeBytes,
		AvailableBytes: availableBytes,
		UsedBytes:      usedBytes,
		UsedPercent:    usedPercent,
	}, nil
}

// CheckDiskSpace checks if there is enough disk space for an upload
// Returns true if space is available, false otherwise with an error message
// skipPercentCheck should be true when quota is configured (quota takes precedence)
func CheckDiskSpace(path string, uploadSize int64, skipPercentCheck bool) (bool, string, error) {
	info, err := GetDiskSpace(path)
	if err != nil {
		return false, "Failed to check disk space", err
	}

	// Check if available space is less than minimum required
	if info.AvailableBytes < MinimumFreeSpace {
		return false, fmt.Sprintf("Insufficient disk space (less than 1GB available)"), nil
	}

	// Check if upload would exceed maximum disk usage percentage
	// Skip this check when quota is configured, as quota is the primary limit
	if !skipPercentCheck {
		projectedUsed := info.UsedBytes + uint64(uploadSize)
		projectedPercent := float64(projectedUsed) / float64(info.TotalBytes) * 100

		if projectedPercent > MaximumDiskUsagePercent {
			return false, fmt.Sprintf("Upload would exceed disk capacity limit (%d%%)", MaximumDiskUsagePercent), nil
		}
	}

	// Check if upload is larger than available space
	if uint64(uploadSize) > info.AvailableBytes {
		return false, "File size exceeds available disk space", nil
	}

	return true, "", nil
}

// FormatBytes formats bytes into human-readable format
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GetPartialUploadsSize calculates the total disk space used by partial uploads
// Returns the total size in bytes of all files in the .partial directory
func GetPartialUploadsSize(uploadDir string) (int64, error) {
	partialDir := filepath.Join(uploadDir, ".partial")

	// Check if .partial directory exists
	if _, err := os.Stat(partialDir); os.IsNotExist(err) {
		return 0, nil // Directory doesn't exist, return 0 bytes
	}

	var totalSize int64

	// Walk through .partial directory and sum all file sizes
	err := filepath.Walk(partialDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip files/directories we can't access
			return nil
		}

		// Only count regular files (not directories)
		if !info.IsDir() {
			totalSize += info.Size()
		}

		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to calculate partial uploads size: %w", err)
	}

	return totalSize, nil
}
