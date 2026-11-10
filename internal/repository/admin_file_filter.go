package repository

import (
	"fmt"
	"slices"
	"time"
)

// Status filter values for AdminFileFilter.Status.
const (
	AdminFileStatusActive       = "active"        // download limit not reached and not expired
	AdminFileStatusLimitReached = "limit_reached" // download_count has reached max_downloads
	AdminFileStatusNeverExpires = "never_expires" // the year-9999 never-expire sentinel
	AdminFileStatusExpiringSoon = "expiring_soon" // expires within AdminFileExpiringSoonWindow
)

// AdminFileExpiringSoonWindow is how far ahead AdminFileStatusExpiringSoon looks.
const AdminFileExpiringSoonWindow = 24 * time.Hour

// Scan filter values for AdminFileFilter.Scan. The first four match a stored
// scan_status; AdminFileScanNotScanned groups every "never inspected" state.
const (
	AdminFileScanClean      = "clean"
	AdminFileScanPending    = "pending"
	AdminFileScanInfected   = "infected"
	AdminFileScanError      = "error"
	AdminFileScanNotScanned = "not_scanned" // scan_status NULL, '', 'skipped' or 'not_scanned'
)

// Sort values for AdminFileFilter.Sort. Empty means AdminFileSortNewest.
const (
	AdminFileSortNewest   = "newest"
	AdminFileSortOldest   = "oldest"
	AdminFileSortLargest  = "largest"
	AdminFileSortSmallest = "smallest"
	AdminFileSortExpiring = "expiring" // soonest first, never-expiring files last
)

// NeverExpireYear is the year of the "never expires" sentinel
// (9999-12-31T23:59:59Z). Any expires_at in that year counts as never.
const NeverExpireYear = 9999

// AdminFileFilter narrows and orders the admin dashboard file list. The zero
// value lists every file, newest first. All conditions are ANDed.
type AdminFileFilter struct {
	// Search matches claim code, filename, uploader IP or username (substring,
	// case-insensitive). Implementations escape LIKE wildcards.
	Search string

	// UserID keeps files uploaded by this user. Anonymous keeps files with no
	// user. At most one of the two may be set.
	UserID    *int64
	Anonymous bool

	// MinSize (inclusive) and MaxSize (exclusive) bound file_size in bytes.
	MinSize *int64
	MaxSize *int64

	Status string // one of the AdminFileStatus* values, or "" for any
	Scan   string // one of the AdminFileScan* values, or "" for any

	// UploadedWithin keeps files created within this long before now;
	// UploadedBefore keeps files created more than this long before now.
	// Zero disables each.
	UploadedWithin time.Duration
	UploadedBefore time.Duration

	Sort string // one of the AdminFileSort* values, or "" for newest
}

// The accepted non-empty values of AdminFileFilter's Status, Scan and Sort.
var (
	AdminFileStatuses = []string{AdminFileStatusActive, AdminFileStatusLimitReached, AdminFileStatusNeverExpires, AdminFileStatusExpiringSoon}
	AdminFileScans    = []string{AdminFileScanClean, AdminFileScanPending, AdminFileScanInfected, AdminFileScanError, AdminFileScanNotScanned}
	AdminFileSorts    = []string{AdminFileSortNewest, AdminFileSortOldest, AdminFileSortLargest, AdminFileSortSmallest, AdminFileSortExpiring}
)

func emptyOrOneOf(v string, allowed []string) bool {
	return v == "" || slices.Contains(allowed, v)
}

// Validate reports the first invalid field, wrapped in ErrInvalidInput.
func (f AdminFileFilter) Validate() error {
	switch {
	case f.UserID != nil && f.Anonymous:
		return fmt.Errorf("%w: a user and anonymous can't both be selected", ErrInvalidInput)
	case f.UserID != nil && *f.UserID <= 0:
		return fmt.Errorf("%w: user id must be a positive integer", ErrInvalidInput)
	case f.MinSize != nil && *f.MinSize < 0:
		return fmt.Errorf("%w: min_size must not be negative", ErrInvalidInput)
	case f.MaxSize != nil && *f.MaxSize <= 0:
		return fmt.Errorf("%w: max_size must be greater than zero", ErrInvalidInput)
	case f.MinSize != nil && f.MaxSize != nil && *f.MinSize >= *f.MaxSize:
		return fmt.Errorf("%w: min_size must be less than max_size", ErrInvalidInput)
	case !emptyOrOneOf(f.Status, AdminFileStatuses):
		return fmt.Errorf("%w: unknown status %q", ErrInvalidInput, f.Status)
	case !emptyOrOneOf(f.Scan, AdminFileScans):
		return fmt.Errorf("%w: unknown scan %q", ErrInvalidInput, f.Scan)
	case !emptyOrOneOf(f.Sort, AdminFileSorts):
		return fmt.Errorf("%w: unknown sort %q", ErrInvalidInput, f.Sort)
	case f.UploadedWithin < 0 || f.UploadedBefore < 0:
		return fmt.Errorf("%w: upload age must not be negative", ErrInvalidInput)
	}
	return nil
}

// AdminUploader is one user who currently has files, for the admin user filter.
type AdminUploader struct {
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	FileCount int    `json:"file_count"`
}

// AdminUploaders counts the files in the admin list per uploader.
type AdminUploaders struct {
	AnonymousCount int             `json:"anonymous_count"`
	Users          []AdminUploader `json:"users"` // sorted by username (case-insensitive), then id
}
