// Package safeshare provides a Go client SDK for the SafeShare file sharing service.
package safeshare

import "time"

// UploadResult represents the result of a successful file upload.
type UploadResult struct {
	// ClaimCode is the unique code for downloading the file.
	ClaimCode string `json:"claim_code"`
	// Filename is the original filename.
	Filename string `json:"filename"`
	// Size is the file size in bytes.
	Size int64 `json:"size"`
	// MimeType is the MIME type of the file.
	MimeType string `json:"mime_type"`
	// ExpiresAt is the expiration time (nil if no expiration).
	ExpiresAt *time.Time `json:"expires_at"`
	// DownloadLimit is the maximum number of downloads (nil if unlimited).
	DownloadLimit *int `json:"download_limit"`
	// PasswordProtected indicates if the file requires a password.
	PasswordProtected bool `json:"password_protected"`
	// UserID is the uploader's user ID (if authenticated).
	UserID *int `json:"user_id,omitempty"`
}

// UploadOptions configures a file upload.
type UploadOptions struct {
	// ExpiresInHours is hours until expiration (nil for no expiration).
	ExpiresInHours *int
	// DownloadLimit is max downloads allowed (nil for unlimited).
	DownloadLimit *int
	// Password protects the file with a password.
	Password string
	// OnProgress is called with upload progress updates.
	OnProgress func(UploadProgress)
}

// UploadProgress provides information about upload progress.
type UploadProgress struct {
	// BytesUploaded is the number of bytes uploaded so far.
	BytesUploaded int64
	// TotalBytes is the total file size.
	TotalBytes int64
	// Percentage is the completion percentage (0-100).
	Percentage int
	// CurrentChunk is the current chunk number (for chunked uploads).
	CurrentChunk int
	// TotalChunks is the total number of chunks (for chunked uploads).
	TotalChunks int
}

// ChunkedUploadSession represents an active chunked upload session.
type ChunkedUploadSession struct {
	// UploadID is the unique identifier for this upload session.
	UploadID string `json:"upload_id"`
	// ChunkSize is the size of each chunk in bytes.
	ChunkSize int64 `json:"chunk_size"`
	// TotalChunks is the expected number of chunks.
	TotalChunks int `json:"total_chunks"`
	// ExpiresAt is when this session expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// ChunkUploadResult represents the result of uploading a single chunk.
type ChunkUploadResult struct {
	// ChunkNumber is the chunk that was uploaded.
	ChunkNumber int `json:"chunk_number"`
	// Size is the size of the uploaded chunk.
	Size int64 `json:"size"`
	// Hash is the SHA-256 hash of the chunk.
	Hash string `json:"hash"`
}

// UploadStatus represents the status of a chunked upload session.
type UploadStatus struct {
	// UploadID is the upload session ID.
	UploadID string `json:"upload_id"`
	// Filename is the original filename.
	Filename string `json:"filename"`
	// TotalSize is the total file size in bytes.
	TotalSize int64 `json:"total_size"`
	// UploadedSize is bytes uploaded so far.
	UploadedSize int64 `json:"uploaded_size"`
	// UploadedChunks is the list of uploaded chunk numbers.
	UploadedChunks []int `json:"uploaded_chunks"`
	// TotalChunks is the expected number of chunks.
	TotalChunks int `json:"total_chunks"`
	// ChunkSize is the size of each chunk.
	ChunkSize int64 `json:"chunk_size"`
	// ExpiresAt is when this session expires.
	ExpiresAt time.Time `json:"expires_at"`
	// Complete indicates if the upload is complete.
	Complete bool `json:"complete"`
	// Status is the current status: uploading, processing, completed, failed.
	Status string `json:"status"`
	// ClaimCode is the claim code (only set when completed).
	ClaimCode *string `json:"claim_code,omitempty"`
	// ErrorMessage is the error message (only set when failed).
	ErrorMessage *string `json:"error_message,omitempty"`
	// MaxDownloads is the maximum download limit (nil if unlimited).
	MaxDownloads *int `json:"max_downloads,omitempty"`
}

// FileInfo represents public file information.
type FileInfo struct {
	// Filename is the original filename.
	Filename string `json:"filename"`
	// Size is the file size in bytes.
	Size int64 `json:"size"`
	// MimeType is the MIME type.
	MimeType string `json:"mime_type"`
	// ExpiresAt is the expiration time (nil if no expiration).
	ExpiresAt *time.Time `json:"expires_at"`
	// PasswordProtected indicates if a password is required.
	PasswordProtected bool `json:"password_protected"`
	// DownloadsRemaining is downloads left (nil if unlimited).
	DownloadsRemaining *int `json:"downloads_remaining"`
}

// UserFile represents a file owned by the authenticated user.
type UserFile struct {
	// ID is the unique file ID.
	ID int `json:"id"`
	// ClaimCode is the download claim code.
	ClaimCode string `json:"claim_code"`
	// Filename is the original filename.
	Filename string `json:"filename"`
	// Size is the file size in bytes.
	Size int64 `json:"size"`
	// MimeType is the MIME type.
	MimeType string `json:"mime_type"`
	// UploadedAt is the upload timestamp.
	UploadedAt time.Time `json:"uploaded_at"`
	// ExpiresAt is the expiration time (nil if no expiration).
	ExpiresAt *time.Time `json:"expires_at"`
	// CompletedDownloads is how many times the file has been fully downloaded.
	CompletedDownloads int `json:"completed_downloads"`
	// DownloadCount is the raw HTTP request count (includes partial/retried downloads).
	// Deprecated: Use CompletedDownloads instead for accurate download counts.
	DownloadCount int `json:"download_count"`
	// DownloadLimit is the max downloads (nil if unlimited).
	DownloadLimit *int `json:"download_limit"`
	// PasswordProtected indicates if the file requires a password.
	PasswordProtected bool `json:"password_protected"`
}

// UserFilesResponse represents a paginated list of user files.
type UserFilesResponse struct {
	// Files is the list of files.
	Files []UserFile `json:"files"`
	// Total is the total number of files.
	Total int `json:"total"`
	// Page is the current page number.
	Page int `json:"page"`
	// PerPage is the number of files per page.
	PerPage int `json:"per_page"`
}

// DownloadOptions configures a file download.
type DownloadOptions struct {
	// Password is required if the file is password-protected.
	Password string
	// OnProgress is called with download progress updates.
	OnProgress func(DownloadProgress)
	// Overwrite allows replacing an existing file at the destination.
	// If false (default), downloading to an existing file returns an error.
	Overwrite bool
}

// DownloadProgress provides information about download progress.
type DownloadProgress struct {
	// BytesDownloaded is bytes downloaded so far.
	BytesDownloaded int64
	// TotalBytes is total bytes to download (0 if unknown).
	TotalBytes int64
	// Percentage is completion percentage (0-100, or -1 if unknown).
	Percentage int
}

// PublicConfig represents the server's public configuration.
type PublicConfig struct {
	// MaxFileSize is the maximum upload size in bytes.
	MaxFileSize int64 `json:"max_file_size"`
	// ChunkUploadThreshold is when to use chunked upload.
	ChunkUploadThreshold int64 `json:"chunked_upload_threshold"`
	// ChunkSize is the size of each chunk.
	ChunkSize int64 `json:"chunk_size"`
	// MaxExpirationHours is the maximum expiration time.
	MaxExpirationHours int `json:"max_expiration_hours"`
	// RegistrationEnabled indicates if user registration is open.
	RegistrationEnabled bool `json:"registration_enabled"`
}

// CreateTokenRequest contains parameters for creating an API token.
type CreateTokenRequest struct {
	// Name is a human-readable token name.
	Name string `json:"name"`
	// Scopes is the list of permissions (upload, download, manage, admin).
	Scopes []string `json:"scopes"`
	// ExpiresInDays is days until expiration (nil for no expiration, max 365).
	ExpiresInDays *int `json:"expires_in_days,omitempty"`
}

// TokenCreatedResponse contains the created token (shown only once).
type TokenCreatedResponse struct {
	// Token is the API token value - save this immediately!
	Token string `json:"token"`
	// Name is the token name.
	Name string `json:"name"`
	// Scopes is the token's permissions.
	Scopes []string `json:"scopes"`
	// ExpiresAt is the expiration time (nil if no expiration).
	ExpiresAt *time.Time `json:"expires_at"`
	// CreatedAt is when the token was created.
	CreatedAt time.Time `json:"created_at"`
}

// TokenInfo represents information about an API token.
type TokenInfo struct {
	// ID is the token's unique ID.
	ID int `json:"id"`
	// Name is the token name.
	Name string `json:"name"`
	// Scopes is the token's permissions.
	Scopes []string `json:"scopes"`
	// ExpiresAt is the expiration time (nil if no expiration).
	ExpiresAt *time.Time `json:"expires_at"`
	// CreatedAt is when the token was created.
	CreatedAt time.Time `json:"created_at"`
	// LastUsedAt is when the token was last used (nil if never).
	LastUsedAt *time.Time `json:"last_used_at"`
}

// ClientConfig contains configuration for creating a SafeShareClient.
type ClientConfig struct {
	// BaseURL is the SafeShare server URL (required).
	BaseURL string
	// APIToken is the API token for authentication (optional).
	APIToken string
	// Timeout is the request timeout (default: 5 minutes).
	Timeout time.Duration
	// InsecureSkipVerify disables TLS certificate verification (dangerous!).
	InsecureSkipVerify bool
}

// apiUploadResponse is the raw API response for uploads.
type apiUploadResponse struct {
	ClaimCode         string  `json:"claim_code"`
	Filename          string  `json:"filename"`
	Size              int64   `json:"size"`
	MimeType          string  `json:"mime_type"`
	ExpiresAt         *string `json:"expires_at"`
	DownloadLimit     *int    `json:"download_limit"`
	PasswordProtected bool    `json:"password_protected"`
	UserID            *int    `json:"user_id,omitempty"`
}

// apiFileInfoResponse is the raw API response for file info.
// Server returns fields from internal/handlers/claim.go:ClaimInfoHandler
type apiFileInfoResponse struct {
	ClaimCode            string  `json:"claim_code"`
	Filename             string  `json:"original_filename"`
	Size                 int64   `json:"file_size"`
	MimeType             string  `json:"mime_type"`
	CreatedAt            string  `json:"created_at"`
	ExpiresAt            *string `json:"expires_at"`
	MaxDownloads         *int    `json:"max_downloads"`
	DownloadCount        int     `json:"download_count"`
	CompletedDownloads   int     `json:"completed_downloads"`
	DownloadLimitReached bool    `json:"download_limit_reached"`
	PasswordProtected    bool    `json:"password_required"`
	DownloadURL          string  `json:"download_url"`
	SHA256Hash           string  `json:"sha256_hash"`
}

// apiUserFileResponse is the raw API response for user files.
type apiUserFileResponse struct {
	ID                 int     `json:"id"`
	ClaimCode          string  `json:"claim_code"`
	OriginalFilename   string  `json:"original_filename"`
	FileSize           int64   `json:"file_size"`
	MimeType           string  `json:"mime_type"`
	CreatedAt          string  `json:"created_at"`
	ExpiresAt          string  `json:"expires_at"`
	DownloadCount      int     `json:"download_count"`
	CompletedDownloads int     `json:"completed_downloads"`
	MaxDownloads       *int    `json:"max_downloads"`
	PasswordProtected  bool    `json:"is_password_protected"`
	DownloadURL        string  `json:"download_url"`
	IsExpired          bool    `json:"is_expired"`
}

// apiUserFilesResponse is the raw API response for listing user files.
type apiUserFilesResponse struct {
	Files  []apiUserFileResponse `json:"files"`
	Total  int                   `json:"total"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
}

// apiConfigResponse is the raw API response for server config.
type apiConfigResponse struct {
	MaxFileSize          int64 `json:"max_file_size"`
	ChunkUploadThreshold int64 `json:"chunked_upload_threshold"`
	ChunkSize            int64 `json:"chunk_size"`
	MaxExpirationHours   int   `json:"max_expiration_hours"`
	RegistrationEnabled  bool  `json:"registration_enabled"`
}

// apiChunkedUploadInitResponse is the raw API response for chunked upload init.
type apiChunkedUploadInitResponse struct {
	UploadID    string `json:"upload_id"`
	ChunkSize   int64  `json:"chunk_size"`
	TotalChunks int    `json:"total_chunks"`
	ExpiresAt   string `json:"expires_at"`
}

// apiTokenInfoResponse is the raw API response for token info.
type apiTokenInfoResponse struct {
	ID         int      `json:"id"`
	Name       string   `json:"name"`
	Scopes     []string `json:"scopes"`
	ExpiresAt  *string  `json:"expires_at"`
	CreatedAt  string   `json:"created_at"`
	LastUsedAt *string  `json:"last_used_at"`
}

// apiTokenCreatedResponse is the raw API response for token creation.
type apiTokenCreatedResponse struct {
	Token     string   `json:"token"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expires_at"`
	CreatedAt string   `json:"created_at"`
}

// apiTokenListResponse is the raw API response for listing tokens.
type apiTokenListResponse struct {
	Tokens []apiTokenInfoResponse `json:"tokens"`
}
