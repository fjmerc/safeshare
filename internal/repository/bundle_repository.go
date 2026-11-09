package repository

import (
	"context"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// BundleRepository stores multi-file bundles. A bundle is created as a
// draft, members are inserted through the normal file paths with
// files.bundle_id set, and Publish makes it reachable by its code.
type BundleRepository interface {
	// Create inserts b and sets b.ID. A duplicate bundle_code returns ErrDuplicateKey.
	Create(ctx context.Context, b *models.Bundle) error

	// GetByID returns the bundle in any status, or nil, nil if it does not exist.
	GetByID(ctx context.Context, id int64) (*models.Bundle, error)

	// GetPublishedByCode returns a published, unexpired bundle, or nil, nil
	// when the code is unknown, still a draft, or expired.
	GetPublishedByCode(ctx context.Context, code string) (*models.Bundle, error)

	// GetMember returns the member at position, or nil, nil if there is none
	// or it has expired.
	GetMember(ctx context.Context, bundleID int64, position int) (*models.File, error)

	// ListMembers returns all member files ordered by position.
	ListMembers(ctx context.Context, bundleID int64) ([]*models.File, error)

	// MemberPositionTaken reports whether a member file, or an incomplete
	// chunked upload, already holds position in the bundle.
	MemberPositionTaken(ctx context.Context, bundleID int64, position int) (bool, error)

	// Publish atomically checks that the draft has exactly the positions
	// 0..file_count-1 with no member pending or infected, then marks it
	// published and stores manifest. A bundle that is not a draft returns
	// ErrNotFound; an incomplete or unclean one returns ErrInvalidInput.
	Publish(ctx context.Context, bundleID int64, manifest []byte) error

	// DeleteWithMembers deletes the member file rows and then the bundle in
	// one transaction, returning the deleted files so the caller can remove
	// their stored data. A missing bundle returns ErrNotFound.
	DeleteWithMembers(ctx context.Context, bundleID int64) ([]*models.File, error)

	// ListByUser returns the user's published bundles, newest first, and the total count.
	ListByUser(ctx context.Context, userID int64, limit, offset int) ([]models.Bundle, int, error)

	// UpdateExpiration sets the expiry of a published bundle and all its
	// members. A bundle the user does not own returns ErrNotFound.
	UpdateExpiration(ctx context.Context, bundleID, userID int64, expiresAt time.Time) error

	// RegenerateCode replaces a published bundle's code. A bundle the user
	// does not own returns ErrNotFound; a code collision returns ErrDuplicateKey.
	RegenerateCode(ctx context.Context, bundleID, userID int64, newCode string) error

	// ListAbandonedDrafts returns ids of drafts created before olderThan.
	ListAbandonedDrafts(ctx context.Context, olderThan time.Time) ([]int64, error)

	// ListEmptyPublished returns ids of published bundles with no members left.
	ListEmptyPublished(ctx context.Context) ([]int64, error)

	// BundleIDForMemberClaimCode returns the bundle a file belongs to, looked
	// up by the file's own claim code (admin tools address files that way).
	// ok is false when no file has that code or the file is standalone.
	BundleIDForMemberClaimCode(ctx context.Context, claimCode string) (bundleID int64, ok bool, err error)
}
