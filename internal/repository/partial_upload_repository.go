package repository

import (
	"context"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// PartialUploadReservationIdle is how long a chunked upload in the uploading
// state keeps its full size reserved against the storage quota without
// storing a new chunk (T30). After that, quota counts only the bytes it has
// actually received, so an /init that never sends data can't hold quota for
// the whole PARTIAL_UPLOAD_EXPIRY_HOURS. The next new chunk re-reserves the
// rest (RenewReservation), or fails with 507 if the quota has since filled.
const PartialUploadReservationIdle = time.Hour

// AssemblyLease describes the fencing token and TTL an assembly worker
// presents when it acquires (or renews) the right to process a partial
// upload. See ADR-016.
type AssemblyLease struct {
	// Owner is a fencing token unique to this attempt, e.g.
	// utils.GetOwnerID()+"/"+uuid.New().String(). Every subsequent
	// owner-guarded call for this attempt (Renew/Yield/Publish/Fail/
	// Release) must pass the same Owner value.
	Owner string
	// TTL is how long the lease is valid for from now. A worker must renew
	// before it expires (see ASSEMBLY_LEASE_TTL) or another attempt may
	// take over the row.
	TTL time.Duration
}

// PartialUploadRepository defines the interface for partial upload (chunked upload) database operations.
// All methods accept a context for cancellation and timeout support.
type PartialUploadRepository interface {
	// Create inserts a new partial upload record.
	Create(ctx context.Context, upload *models.PartialUpload) error

	// CreateWithQuotaCheck atomically checks quota and creates a partial upload record.
	// Returns ErrQuotaExceeded if adding the upload would exceed the quota limit.
	// This prevents race conditions where multiple uploads could exceed quota.
	CreateWithQuotaCheck(ctx context.Context, upload *models.PartialUpload, quotaLimitBytes int64) error

	// GetByUploadID retrieves a partial upload by upload_id.
	// Returns nil, nil if not found.
	GetByUploadID(ctx context.Context, uploadID string) (*models.PartialUpload, error)

	// Exists checks if a partial upload record exists in the database.
	Exists(ctx context.Context, uploadID string) (bool, error)

	// UpdateActivity updates the last_activity timestamp. Chunk uploads use
	// RecordChunkProgress instead, which also tracks received_bytes (T30).
	UpdateActivity(ctx context.Context, uploadID string) error

	// IncrementChunksReceived increments chunks_received and received_bytes.
	IncrementChunksReceived(ctx context.Context, uploadID string, chunkBytes int64) error

	// RecordChunkProgress marks a newly stored chunk of an upload still in the
	// uploading state: it refreshes last_activity and raises received_bytes to
	// receivedBytes (capped at total_size, never lowered, so out-of-order
	// updates from parallel chunks are harmless).
	RecordChunkProgress(ctx context.Context, uploadID string, receivedBytes int64) error

	// RenewReservation re-reserves the rest of an upload's size against the
	// quota once its reservation has lapsed (see PartialUploadReservationIdle).
	// It is a no-op for an upload whose reservation is still held, so parallel
	// chunks can't charge it twice. Returns ErrQuotaExceeded if the remaining
	// bytes no longer fit.
	RenewReservation(ctx context.Context, uploadID string, quotaLimitBytes int64) error

	// Delete removes a partial upload record.
	Delete(ctx context.Context, uploadID string) error

	// GetAbandoned returns partial uploads that haven't been active for the specified hours
	// and are not completed. A row currently held by a live (unexpired) assembly lease is
	// never returned, regardless of last_activity — only a lease that has actually expired
	// (or a plain uploading-state timeout) counts as abandoned.
	GetAbandoned(ctx context.Context, expiryHours int) ([]models.PartialUpload, error)

	// GetOldCompleted returns completed uploads, and terminally-failed uploads
	// (error_retryable = false), older than the specified hours. These are
	// kept for idempotency/visibility and cleaned up after retention period.
	GetOldCompleted(ctx context.Context, retentionHours int) ([]models.PartialUpload, error)

	// GetByUserID returns all partial uploads for a specific user.
	GetByUserID(ctx context.Context, userID int64) ([]models.PartialUpload, error)

	// GetTotalUsage returns the total bytes used by active (incomplete) partial uploads.
	GetTotalUsage(ctx context.Context) (int64, error)

	// GetIncompleteCount returns the count of incomplete partial upload sessions.
	GetIncompleteCount(ctx context.Context) (int, error)

	// GetAllUploadIDs returns all upload_ids currently in the database as a set.
	// This is optimized for orphaned chunk detection to avoid N+1 queries.
	GetAllUploadIDs(ctx context.Context) (map[string]bool, error)

	// Assembly state machine (ADR-016). Status values are unchanged
	// (uploading/processing/completed/failed); every processing/failed
	// transition below is a compare-and-swap guarded by status and/or
	// owner, so at most one caller ever wins a given transition.

	// UpdateStatus updates the status and error_message (if provided).
	// Retained for legacy/manual state fixups; assembly code paths should
	// prefer the CAS methods below.
	UpdateStatus(ctx context.Context, uploadID, status string, errorMessage *string) error

	// TryLockForProcessing performs the Lock transition: uploading -> processing.
	// On success it sets owner=lease.Owner, lease_expires_at=now+lease.TTL,
	// assembly_attempts+=1, assembly_started_at=now, and clears error_*.
	// Returns true if the CAS matched (lock acquired).
	TryLockForProcessing(ctx context.Context, uploadID string, lease AssemblyLease) (bool, error)

	// LockFailedForProcessing performs the Reopen-and-Lock transition in a
	// single atomic step: failed -> processing, only when error_retryable is
	// true and assembly_attempts < maxAttempts. Sets owner=lease.Owner,
	// lease_expires_at=now+lease.TTL, assembly_attempts+=1,
	// assembly_started_at=now, and clears error_*. Returns true if the CAS
	// matched.
	//
	// This is deliberately one step, not Reopen (failed -> uploading) then a
	// separate TryLockForProcessing (uploading -> processing): splitting it
	// in two left a window where a preflight failure (missing chunks,
	// integrity, disk space, assembly-queue saturation) between the steps
	// stranded the row in "uploading" — a status the recovery sweep never
	// looks at (ADR-016 bug-hunter finding M2). Callers MUST run every
	// preflight check before calling this, so a failure leaves the original
	// "failed" (retryable) row untouched rather than orphaning it in a
	// different, unrecoverable state.
	LockFailedForProcessing(ctx context.Context, uploadID string, lease AssemblyLease, maxAttempts int) (bool, error)

	// TakeOverExpiredLease performs the TakeOver transition: processing ->
	// processing, only when the current lease is NULL or expired AND
	// assembly_attempts < maxAttempts. Installs a fresh owner/lease and
	// increments assembly_attempts. Returns true if the CAS matched.
	TakeOverExpiredLease(ctx context.Context, uploadID string, lease AssemblyLease, maxAttempts int) (bool, error)

	// ExhaustExpiredLease performs the Exhaust transition: processing ->
	// failed (terminal), only when the current lease is NULL or expired AND
	// assembly_attempts >= maxAttempts. Sets error_code=ASSEMBLY_RETRIES_EXHAUSTED,
	// error_retryable=false. Returns true if the CAS matched.
	ExhaustExpiredLease(ctx context.Context, uploadID string, maxAttempts int) (bool, error)

	// RenewAssemblyLease performs the Renew (heartbeat) transition:
	// processing -> processing, only when status='processing' AND
	// owner=lease.Owner. Extends lease_expires_at to now+lease.TTL. Returns
	// true if the CAS matched; false (with a nil error) means the caller no
	// longer owns the row and must stop working on it.
	RenewAssemblyLease(ctx context.Context, uploadID string, lease AssemblyLease) (bool, error)

	// YieldAssemblyLease performs the Yield transition: processing ->
	// processing, only when status='processing' AND owner=owner. Sets
	// lease_expires_at=now (i.e. "expire it now") so recovery can take over
	// immediately instead of waiting out the full TTL — used when a worker
	// is asked to stop mid-assembly (server shutdown).
	YieldAssemblyLease(ctx context.Context, uploadID, owner string) error

	// ReleaseProcessingLock performs the Release transition: processing ->
	// processing (status unchanged), only when status='processing' AND
	// owner=owner. Decrements assembly_attempts (undoing the increment
	// Lock/LockFailedForProcessing/TakeOverExpiredLease made for this
	// attempt) and force-expires the lease (like YieldAssemblyLease), so
	// the row is immediately eligible for the next takeover — by the
	// background recovery sweep OR an inline retry — instead of only a
	// status a client itself happens to poll.
	//
	// Used to unwind a lock taken speculatively before a worker was ever
	// spawned (assembly-queue saturation, or a shutdown/StartAssembly race
	// in UploadCompleteHandler or the recovery sweep). Earlier this reverted
	// status all the way to 'uploading', which was wrong whenever the lock
	// had actually come from 'failed' (LockFailedForProcessing) or from
	// another 'processing' row (TakeOverExpiredLease): the row ended up
	// stranded in 'uploading', a status the recovery sweep never scans
	// (ADR-016 bug-hunter findings M2/L2). Returns true if the row matched.
	ReleaseProcessingLock(ctx context.Context, uploadID, owner string) (bool, error)

	// GetExpiredLeases returns up to limit uploads in "processing" status
	// whose lease has expired (or was never set), oldest lease first. Used
	// by the recovery worker to find takeover candidates. limit <= 0 means
	// no limit.
	GetExpiredLeases(ctx context.Context, limit int) ([]models.PartialUpload, error)

	// ExpireAllLeases force-expires every "processing" row's lease
	// (lease_expires_at = now). Called once at SQLite startup, before the
	// HTTP server starts accepting requests: since SQLite is single-process,
	// any row still "processing" at boot belongs to a worker that died with
	// the previous process, so its lease can never be legitimately renewed.
	// Not required for PostgreSQL (multi-process HA), where the TTL alone
	// is sufficient.
	ExpireAllLeases(ctx context.Context) error

	// PublishAssembly performs the Publish transition: processing ->
	// completed, only when status='processing' AND owner=owner (the lease
	// itself may already be expired — the owner token is the fence, not the
	// TTL). In the SAME transaction it also inserts the given file record
	// (file.PartialUploadID is set to uploadID) and sets file.ID on success.
	// Returns ErrLeaseLost if the CAS didn't match (a takeover already won),
	// or ErrDuplicateKey if a file row for this upload_id already exists
	// (double-publish attempt).
	PublishAssembly(ctx context.Context, uploadID, owner string, file *models.File) error

	// FailAssembly performs the Fail transition: processing -> failed, only
	// when status='processing' AND owner=owner. Sets error_message,
	// error_code (may be ""  for no specific code) and error_retryable. When
	// auditFile is non-nil (malware-detected audit trail), it is inserted in
	// the SAME transaction as the status update. Returns ErrLeaseLost if the
	// CAS didn't match.
	FailAssembly(ctx context.Context, uploadID, owner, errorMessage, errorCode string, retryable bool, auditFile *models.File) error

	// DeleteIfAbandoned atomically deletes the row only if it still matches
	// the abandoned criteria at delete time (same shape as GetAbandoned's
	// WHERE clause, re-evaluated), preventing a race where a row becomes
	// active again between being listed and being deleted. Returns true if
	// a row was deleted.
	DeleteIfAbandoned(ctx context.Context, uploadID string, expiryHours int) (bool, error)
}
