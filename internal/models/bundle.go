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
