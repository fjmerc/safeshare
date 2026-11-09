package models

import "time"

// Bundle status values. A bundle is created as a draft, members are uploaded
// into it, and it becomes reachable by its code only once published.
const (
	BundleStatusDraft     = "draft"
	BundleStatusPublished = "published"
)

// Bundle is a set of files shared under one code and one link. It owns its
// member files (files.bundle_id); its settings are mirrored onto every member
// row so the existing expiry, password and download-limit code enforces them.
type Bundle struct {
	ID                int64
	BundleCode        string
	Status            string // BundleStatusDraft or BundleStatusPublished
	FileCount         int    // number of members the bundle was created for
	UploadTokenHash   string // SHA-256 hex of the bearer token that may add members to the draft; the token itself is never stored
	CreatedAt         time.Time
	PublishedAt       *time.Time
	ExpiresAt         time.Time
	MaxDownloads      *int   // per member file; nil means unlimited
	PasswordHash      string // bcrypt hash; empty means no password
	UserID            *int64
	ClientEncrypted   bool
	EncryptedManifest []byte // opaque client-encrypted file list (E2E bundles only); nil otherwise
	UploaderIP        string
}

// BundleCreateRequest is the body of POST /api/bundles.
type BundleCreateRequest struct {
	FileCount       int      `json:"file_count"`
	ExpiresInHours  *float64 `json:"expires_in_hours"` // nil = server default; 0 = never expire
	MaxDownloads    int      `json:"max_downloads"`    // per file; 0 = unlimited
	Password        string   `json:"password,omitempty"`
	ClientEncrypted bool     `json:"client_encrypted,omitempty"`
}

// BundleCreateResponse is returned by POST /api/bundles. UploadToken is a
// bearer credential for adding members to, publishing or deleting the
// draft; it is shown once and only its hash is stored.
type BundleCreateResponse struct {
	BundleID    int64     `json:"bundle_id"`
	BundleCode  string    `json:"bundle_code"`
	UploadToken string    `json:"upload_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// BundleMemberUploadResponse is returned for a file uploaded into a bundle.
// It deliberately carries no claim code: members are reachable only through
// their bundle.
type BundleMemberUploadResponse struct {
	BundleID         int64  `json:"bundle_id"`
	BundlePosition   int    `json:"bundle_position"`
	OriginalFilename string `json:"original_filename"`
	FileSize         int64  `json:"file_size"`
}

// BundleFileInfo describes one member in a published bundle.
type BundleFileInfo struct {
	Position int    `json:"position"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	MimeType string `json:"mime_type"`
}

// BundleResponse is returned when a bundle is published.
type BundleResponse struct {
	BundleCode      string           `json:"bundle_code"`
	BundleURL       string           `json:"bundle_url"` // E2E bundles: the client appends /key/{key}
	ExpiresAt       time.Time        `json:"expires_at"`
	MaxDownloads    *int             `json:"max_downloads"` // per file; null = unlimited
	ClientEncrypted bool             `json:"client_encrypted"`
	Files           []BundleFileInfo `json:"files"`
}
