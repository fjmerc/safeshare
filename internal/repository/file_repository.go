package repository

import (
	"context"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// ExpiredFileCallback is called for each successfully deleted expired file.
// Parameters: claimCode, filename, fileSize, mimeType, expiresAt
type ExpiredFileCallback func(claimCode, filename string, fileSize int64, mimeType string, expiresAt time.Time)

// ReservationTokenUnlimited is the sentinel token returned by ReserveDownload for files
// with no download cap (max_downloads = NULL or 0). Callers must skip Commit/Cancel for
// this token — no database row was created.
const ReservationTokenUnlimited = "unlimited"

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
	//
	// Deprecated: replaced by the ReserveDownload / CommitDownload / CancelDownload
	// two-phase pattern (SH-2.3; see ADR-012). Kept for one release for any out-of-tree
	// callers; will be removed in v1.7. New code MUST use the reservation methods so the
	// counter isn't consumed before bytes are actually delivered.
	TryIncrementDownloadWithLimit(ctx context.Context, id int64, expectedClaimCode string) (bool, error)

	// ReserveDownload atomically checks the limit and creates a new reservation row.
	// Returns (token, nil) on success; the token is opaque and must be passed back to
	// Commit or Cancel. Returns ("", nil) when the file is at its limit
	// (download_count + in_flight_reservations >= max_downloads).
	// Returns ("", ErrClaimCodeChanged) if the claim code changed between the
	// handler's GetByClaimCode and this call.
	//
	// Files with max_downloads = NULL or 0 bypass the database entirely and return
	// the literal token ReservationTokenUnlimited. Callers must skip Commit/Cancel
	// for that token.
	ReserveDownload(ctx context.Context, fileID int64, expectedClaimCode string) (string, error)

	// CommitDownload finalises a reservation: deletes the row, decrements
	// in_flight_reservations, increments download_count (and completed_downloads,
	// since under SH-2.3 a Commit always implies a successful full-file delivery).
	//
	// Idempotent: a second call with the same token is a no-op.
	//
	// Reaped-mid-stream recovery: if the token has been deleted by the reaper (TTL
	// exceeded), the method attempts to atomically re-acquire a slot. If no slot is
	// available, the function logs a warning and returns nil — the bytes were
	// already delivered, so the counter is allowed to under-report rather than
	// over-report.
	//
	// Unlimited-cap files: when token == ReservationTokenUnlimited (returned by
	// ReserveDownload for files with no max_downloads cap), Commit increments
	// download_count + completed_downloads without touching download_reservations.
	// Callers MUST still call Commit (or Cancel, which is a no-op for the sentinel)
	// to credit the counter — the sentinel is opaque from the caller's perspective.
	CommitDownload(ctx context.Context, fileID int64, token string) error

	// CancelDownload releases a reservation without crediting a download. Decrements
	// in_flight_reservations and deletes the reservation row. Idempotent: a second
	// call with the same token (or a Cancel after a successful Commit) is a no-op.
	//
	// No-op for token == ReservationTokenUnlimited.
	CancelDownload(ctx context.Context, fileID int64, token string) error

	// ReapStaleReservations deletes reservation rows whose age exceeds `ttl` and
	// decrements files.in_flight_reservations accordingly. Returns the count of
	// rows reaped. Called by StartReservationReaper on its 1-minute tick.
	//
	// The cutoff is computed inside the SQL using the DB server's clock
	// (e.g. NOW() - ttl in Postgres, datetime('now', '-N seconds') in SQLite)
	// rather than Go-side `time.Now().Add(-ttl)`. This avoids a class of bug
	// (bug-hunter M4) where wall-clock skew between the application and the DB
	// — or a forward NTP step on a single host — would mass-reap legitimate
	// in-flight reservations. Negative or zero TTLs are accepted (used by tests
	// to mean "reap everything created before now"); the reaper goroutine clamps
	// production values to the documented [1m, 24h] window.
	ReapStaleReservations(ctx context.Context, ttl time.Duration) (int, error)

	// IncrementCompletedDownloads increments the completed downloads counter.
	// This should only be called for full file downloads (HTTP 200 OK),
	// not for partial/range downloads (HTTP 206).
	//
	// Deprecated: under SH-2.3 / ADR-012 the counter is incremented inside
	// CommitDownload so it stays in lock-step with download_count. This method is
	// preserved for the small set of code paths that don't yet use reservations
	// (and the test helpers in the mock). Removal tracked for v1.7.
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

	// UpdateScanStatus updates the malware scan status for a file.
	// status should be one of: "pending", "clean", "infected", "error", "skipped"
	// result contains the virus name or error message (empty for clean/skipped).
	UpdateScanStatus(ctx context.Context, id int64, status string, result string) error
}
