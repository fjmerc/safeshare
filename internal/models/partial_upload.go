package models

import "time"

// PartialUpload represents a chunked upload session in progress
type PartialUpload struct {
	UploadID            string     `json:"upload_id"`
	UserID              *int64     `json:"user_id,omitempty"`
	Filename            string     `json:"filename"`
	TotalSize           int64      `json:"total_size"`
	ChunkSize           int64      `json:"chunk_size"`
	TotalChunks         int        `json:"total_chunks"`
	ChunksReceived      int        `json:"chunks_received"`
	ReceivedBytes       int64      `json:"received_bytes"`
	ExpiresInHours      int        `json:"expires_in_hours"`
	MaxDownloads        int        `json:"max_downloads"`
	PasswordHash        string     `json:"-"` // Never expose hash in JSON
	CreatedAt           time.Time  `json:"created_at"`
	LastActivity        time.Time  `json:"last_activity"`
	Completed           bool       `json:"completed"`
	ClaimCode           *string    `json:"claim_code,omitempty"`
	Status              string     `json:"status"` // uploading, processing, completed, failed
	ErrorMessage        *string    `json:"error_message,omitempty"`
	ErrorCode           *string    `json:"error_code,omitempty"` // Machine-readable failure reason, e.g. MALWARE_DETECTED, SCAN_UNAVAILABLE (ADR-015)
	AssemblyStartedAt   *time.Time `json:"assembly_started_at,omitempty"`
	AssemblyCompletedAt *time.Time `json:"assembly_completed_at,omitempty"`
	ClientEncrypted     bool       `json:"client_encrypted"` // True when contents were encrypted in the browser before upload (E2E)

	// ADR-016 assembly lease fields. Owner is a fencing token
	// (utils.GetOwnerID()+"/"+uuid, unique per lock attempt) that guards
	// every processing->* transition: PublishAssembly/FailAssembly only
	// succeed when the row's owner still matches, so a worker that lost its
	// lease to a takeover can never clobber the winner's result.
	Owner            *string    `json:"-"` // Never exposed to clients; internal fencing token only.
	LeaseExpiresAt   *time.Time `json:"-"`
	AssemblyAttempts int        `json:"assembly_attempts"`
	// ErrorRetryable is persisted at failure time (see assemblyFailure in
	// assembly_worker.go) so /complete and /status can tell a transient
	// failure (SCAN_UNAVAILABLE, ASSEMBLY_FAILED) from a terminal one
	// (MALWARE_DETECTED, INTEGRITY_ERROR, ASSEMBLY_RETRIES_EXHAUSTED)
	// without re-deriving it from ErrorCode.
	ErrorRetryable bool `json:"-"`
	// UploaderIP is set at init time (storeIP) so recovery/takeover keeps
	// the real uploader IP instead of a synthetic "recovery-worker" value.
	UploaderIP string `json:"-"`
}

// UploadInitRequest represents the request to initialize a chunked upload
type UploadInitRequest struct {
	Filename        string `json:"filename"`
	TotalSize       int64  `json:"total_size"`
	ChunkSize       int64  `json:"chunk_size"`
	ExpiresInHours  int    `json:"expires_in_hours"`
	MaxDownloads    int    `json:"max_downloads"`
	Password        string `json:"password,omitempty"`
	ClientEncrypted bool   `json:"client_encrypted,omitempty"`
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
	UploadID           string    `json:"upload_id"`
	Filename           string    `json:"filename"`
	ChunksReceived     int       `json:"chunks_received"`
	TotalChunks        int       `json:"total_chunks"`
	MissingChunks      []int     `json:"missing_chunks,omitempty"`
	Complete           bool      `json:"complete"`
	ExpiresAt          time.Time `json:"expires_at"`
	ClaimCode          *string   `json:"claim_code,omitempty"`
	Status             string    `json:"status"` // uploading, processing, completed, failed
	ErrorMessage       *string   `json:"error_message,omitempty"`
	ErrorCode          *string   `json:"error_code,omitempty"`   // Machine-readable failure reason, e.g. MALWARE_DETECTED, SCAN_UNAVAILABLE (ADR-015)
	Retryable          bool      `json:"retryable"`              // ADR-016: whether a "failed" status can be retried via /complete
	Attempts           int       `json:"attempts"`               // ADR-016: number of assembly attempts made so far
	DownloadURL        *string   `json:"download_url,omitempty"` // Only set when completed
	FileSize           int64     `json:"file_size"`
	MaxDownloads       int       `json:"max_downloads"`
	CompletedDownloads int       `json:"completed_downloads"`
}

// UploadCompleteResponse represents the response after completing a chunked upload
type UploadCompleteResponse struct {
	ClaimCode          string    `json:"claim_code"`
	DownloadURL        string    `json:"download_url"`
	OriginalFilename   string    `json:"original_filename"`
	FileSize           int64     `json:"file_size"`
	ExpiresAt          time.Time `json:"expires_at"`
	MaxDownloads       int       `json:"max_downloads"`
	CompletedDownloads int       `json:"completed_downloads"` // Always 0 for new uploads
}

// UploadCompleteErrorResponse represents an error response with missing chunks
type UploadCompleteErrorResponse struct {
	Error         string `json:"error"`
	Code          string `json:"code"`
	MissingChunks []int  `json:"missing_chunks,omitempty"`
}
