package models

import "time"

// File represents a file record in the database
type File struct {
	ID               int64
	ClaimCode        string
	OriginalFilename string
	StoredFilename   string
	FileSize         int64
	MimeType         string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	MaxDownloads     *int // nullable - nil means unlimited
	DownloadCount    int
	UploaderIP       string
}

// UploadResponse is the JSON response returned after a successful upload
type UploadResponse struct {
	ClaimCode        string    `json:"claim_code"`
	ExpiresAt        time.Time `json:"expires_at"`
	DownloadURL      string    `json:"download_url"`
	MaxDownloads     *int      `json:"max_downloads"`
	FileSize         int64     `json:"file_size"`
	OriginalFilename string    `json:"original_filename"`
}

// ErrorResponse is the JSON error response
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// HealthResponse is the JSON response for the health check endpoint
type HealthResponse struct {
	Status           string `json:"status"`
	UptimeSeconds    int64  `json:"uptime_seconds"`
	TotalFiles       int    `json:"total_files"`
	StorageUsedBytes int64  `json:"storage_used_bytes"`
}
