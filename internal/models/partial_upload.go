package models

import "time"

// PartialUpload represents a chunked upload session in progress
type PartialUpload struct {
	UploadID             string     `json:"upload_id"`
	UserID               *int64     `json:"user_id,omitempty"`
	Filename             string     `json:"filename"`
	TotalSize            int64      `json:"total_size"`
	ChunkSize            int64      `json:"chunk_size"`
	TotalChunks          int        `json:"total_chunks"`
	ChunksReceived       int        `json:"chunks_received"`
	ReceivedBytes        int64      `json:"received_bytes"`
	ExpiresInHours       int        `json:"expires_in_hours"`
	MaxDownloads         int        `json:"max_downloads"`
	PasswordHash         string     `json:"-"` // Never expose hash in JSON
	FileHash             string     `json:"file_hash,omitempty"` // Expected SHA256 of assembled file
	CreatedAt            time.Time  `json:"created_at"`
	LastActivity         time.Time  `json:"last_activity"`
	Completed            bool       `json:"completed"`
	ClaimCode            *string    `json:"claim_code,omitempty"`
	Status               string     `json:"status"` // uploading, processing, completed, failed
	ErrorMessage         *string    `json:"error_message,omitempty"`
	AssemblyStartedAt    *time.Time `json:"assembly_started_at,omitempty"`
	AssemblyCompletedAt  *time.Time `json:"assembly_completed_at,omitempty"`
}

// UploadInitRequest represents the request to initialize a chunked upload
type UploadInitRequest struct {
	Filename        string  `json:"filename"`
	TotalSize       int64   `json:"total_size"`
	ChunkSize       int64   `json:"chunk_size"`
	ExpiresInHours  int     `json:"expires_in_hours"`
	MaxDownloads    int     `json:"max_downloads"`
	Password        string  `json:"password,omitempty"`
	FileHash        string  `json:"file_hash,omitempty"` // SHA256 of entire file (optional)
}

// UploadInitResponse represents the response after initializing a chunked upload
type UploadInitResponse struct {
	UploadID    string    `json:"upload_id"`
	ChunkSize   int64     `json:"chunk_size"`
	TotalChunks int       `json:"total_chunks"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// UploadChunkResponse represents the response after uploading a chunk
type UploadChunkResponse struct {
	UploadID       string `json:"upload_id"`
	ChunkNumber    int    `json:"chunk_number"`
	ChunksReceived int    `json:"chunks_received"`
	TotalChunks    int    `json:"total_chunks"`
	Complete       bool   `json:"complete"`
	Checksum       string `json:"checksum,omitempty"` // SHA256 of uploaded chunk
}

// UploadStatusResponse represents the response for upload status requests
type UploadStatusResponse struct {
	UploadID       string    `json:"upload_id"`
	Filename       string    `json:"filename"`
	ChunksReceived int       `json:"chunks_received"`
	TotalChunks    int       `json:"total_chunks"`
	MissingChunks  []int     `json:"missing_chunks,omitempty"`
	Complete       bool      `json:"complete"`
	ExpiresAt      time.Time `json:"expires_at"`
	ClaimCode      *string   `json:"claim_code,omitempty"`
	Status         string    `json:"status"` // uploading, processing, completed, failed
	ErrorMessage   *string   `json:"error_message,omitempty"`
	DownloadURL    *string   `json:"download_url,omitempty"` // Only set when completed
}

// UploadCompleteResponse represents the response after completing a chunked upload
type UploadCompleteResponse struct {
	ClaimCode        string    `json:"claim_code"`
	DownloadURL      string    `json:"download_url"`
	OriginalFilename string    `json:"original_filename"`
	FileSize         int64     `json:"file_size"`
	ExpiresAt        time.Time `json:"expires_at"`
	MaxDownloads     int       `json:"max_downloads"`
}

// UploadCompleteErrorResponse represents an error response with missing chunks
type UploadCompleteErrorResponse struct {
	Error         string `json:"error"`
	MissingChunks []int  `json:"missing_chunks,omitempty"`
}
