package repository

import (
	"context"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// ExpiredFileCallback is called for each successfully deleted expired file.
// Parameters: claimCode, filename, fileSize, mimeType, expiresAt
type ExpiredFileCallback func(claimCode, filename string, fileSize int64, mimeType string, expiresAt time.Time)

// FileRepository defines the interface for file-related database operations.
// All methods accept a context for cancellation and timeout support.
type FileRepository interface {
	// Create inserts a new file record into the database.
	// The file.ID field will be populated with the generated ID on success.
	Create(ctx context.Context, file *models.File) error

	// CreateWithQuotaCheck atomically checks quota and creates a file record.
	// Returns ErrQuotaExceeded if adding the file would exceed the quota limit.
	// This prevents race conditions where multiple uploads could exceed quota.
	CreateWithQuotaCheck(ctx context.Context, file *models.File, quotaLimitBytes int64) error

	// GetByID retrieves a file by its database ID.
	// Returns ErrNotFound if the file doesn't exist.
	GetByID(ctx context.Context, id int64) (*models.File, error)

	// GetByClaimCode retrieves a file by its claim code.
	// Returns nil, nil if not found or expired (for backward compatibility).
	// Does NOT return expired files.
	GetByClaimCode(ctx context.Context, claimCode string) (*models.File, error)

	// IncrementDownloadCount atomically increments the download counter.
	// Returns ErrNotFound if the file doesn't exist.
	IncrementDownloadCount(ctx context.Context, id int64) error

	// IncrementDownloadCountIfUnchanged increments download count only if claim code matches.
	// Returns ErrClaimCodeChanged if the claim code was modified during the operation.
	IncrementDownloadCountIfUnchanged(ctx context.Context, id int64, expectedClaimCode string) error

	// TryIncrementDownloadWithLimit atomically increments download count if under limit.
	// Returns (true, nil) if increment succeeded.
	// Returns (false, nil) if download limit was reached.
	// Returns (false, ErrClaimCodeChanged) if claim code changed during operation.
	TryIncrementDownloadWithLimit(ctx context.Context, id int64, expectedClaimCode string) (bool, error)

	// IncrementCompletedDownloads increments the completed downloads counter.
	// This should only be called for full file downloads (HTTP 200 OK),
	// not for partial/range downloads (HTTP 206).
	IncrementCompletedDownloads(ctx context.Context, id int64) error

	// Delete removes a file record by ID.
	// Returns ErrNotFound if the file doesn't exist.
	Delete(ctx context.Context, id int64) error

	// DeleteByClaimCode removes a file record by claim code.
	// Returns the deleted file information and nil on success.
	// Returns nil and ErrNotFound if the file doesn't exist.
	DeleteByClaimCode(ctx context.Context, claimCode string) (*models.File, error)

	// DeleteByClaimCodes removes multiple files by claim codes (bulk operation).
	// Returns the list of deleted files (may be fewer than requested if some don't exist).
	DeleteByClaimCodes(ctx context.Context, claimCodes []string) ([]*models.File, error)

	// DeleteExpired removes expired files from database and filesystem.
	// The uploadDir parameter specifies the directory containing physical files.
	// The onExpired callback is called for each successfully deleted file.
	// Returns the count of deleted files.
	//
	// ATOMICITY: For each file, deletes filesystem file first, then DB record.
	// If filesystem deletion fails, the DB record is preserved for retry.
	// The onExpired callback is called ONLY for fully successful deletions.
	DeleteExpired(ctx context.Context, uploadDir string, onExpired ExpiredFileCallback) (int, error)

	// GetTotalUsage returns the total storage used by active files and partial uploads.
	// This includes both completed files and incomplete chunked uploads.
	GetTotalUsage(ctx context.Context) (int64, error)

	// GetStats returns statistics about file storage.
	// The uploadDir parameter is used to calculate filesystem-level metrics if needed.
	GetStats(ctx context.Context, uploadDir string) (*FileStats, error)

	// GetAll returns all files in the database (including expired files).
	// This is primarily used for administrative tools like migration utilities.
	GetAll(ctx context.Context) ([]*models.File, error)

	// GetAllStoredFilenames returns all stored filenames as a set.
	// This is optimized for orphan detection to avoid N+1 queries.
	// Includes both active and expired files.
	GetAllStoredFilenames(ctx context.Context) (map[string]bool, error)

	// GetAllForAdmin returns all files with pagination for admin dashboard.
	// Includes username via join with users table.
	// Returns (files, totalCount, error).
	GetAllForAdmin(ctx context.Context, limit, offset int) ([]models.File, int, error)

	// SearchForAdmin searches files by claim code, filename, IP, or username.
	// Returns (files, totalCount, error).
	//
	// SECURITY: Implementation MUST use parameterized queries and escape
	// LIKE wildcards (% and _) in searchTerm to prevent injection.
	SearchForAdmin(ctx context.Context, searchTerm string, limit, offset int) ([]models.File, int, error)
}
