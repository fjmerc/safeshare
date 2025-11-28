package models

import "time"

// File represents a file record in the database
type File struct {
	ID                 int64
	ClaimCode          string
	OriginalFilename   string
	StoredFilename     string
	FileSize           int64
	MimeType           string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	MaxDownloads       *int // nullable - nil means unlimited
	DownloadCount      int
	CompletedDownloads int // Tracks only successfully completed full file downloads (HTTP 200 OK)
	UploaderIP         string
	PasswordHash       string  // bcrypt hash - empty string means no password
	UserID             *int64  // nullable - nil means no associated user (anonymous upload or legacy)
	Username           *string // optional - populated in admin queries for display purposes
	SHA256Hash         string  // SHA256 checksum of original file (before encryption) - empty for legacy files
}

// UploadResponse is the JSON response returned after a successful upload
type UploadResponse struct {
	ClaimCode          string    `json:"claim_code"`
	ExpiresAt          time.Time `json:"expires_at"`
	DownloadURL        string    `json:"download_url"`
	MaxDownloads       *int      `json:"max_downloads"`
	CompletedDownloads int       `json:"completed_downloads"` // Always 0 for new uploads
	FileSize           int64     `json:"file_size"`
	OriginalFilename   string    `json:"original_filename"`
}

// ErrorResponse is the JSON error response
type ErrorResponse struct {
	Error            string `json:"error"`
	Code             string `json:"code"`
	RetryRecommended *bool  `json:"retry_recommended,omitempty"` // Whether client should retry
	RetryAfter       *int   `json:"retry_after,omitempty"`       // Seconds to wait before retry
}

// HealthResponse is the JSON response for the health check endpoint
type HealthResponse struct {
	Status             string           `json:"status"`
	StatusDetails      []string         `json:"status_details,omitempty"` // Details when status is degraded or unhealthy
	UptimeSeconds      int64            `json:"uptime_seconds"`
	TotalFiles         int              `json:"total_files"`
	StorageUsedBytes   int64            `json:"storage_used_bytes"`
	DiskTotalBytes     uint64           `json:"disk_total_bytes,omitempty"`
	DiskFreeBytes      uint64           `json:"disk_free_bytes,omitempty"`
	DiskUsedPercent    float64          `json:"disk_used_percent,omitempty"`
	DiskAvailableBytes uint64           `json:"disk_available_bytes,omitempty"`
	QuotaLimitBytes    int64            `json:"quota_limit_bytes,omitempty"`  // 0 = unlimited
	QuotaUsedPercent   float64          `json:"quota_used_percent,omitempty"` // Only present when quota is set
	DatabaseMetrics    *DatabaseMetrics `json:"database_metrics,omitempty"`   // Database performance metrics
}

// DatabaseMetrics contains database performance and health information
type DatabaseMetrics struct {
	SizeBytes    int64   `json:"size_bytes"`               // Total database file size
	SizeMB       float64 `json:"size_mb"`                  // Size in megabytes
	WALSizeBytes int64   `json:"wal_size_bytes,omitempty"` // Write-Ahead Log size
	PageCount    int64   `json:"page_count"`               // Total number of pages
	PageSize     int64   `json:"page_size"`                // Size of each page in bytes
	IndexCount   int     `json:"index_count"`              // Total number of indexes
}
