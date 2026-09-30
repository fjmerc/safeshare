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

// Probe-threshold tuning for the ADR-014 commit policy (see ProbeThreshold /
// ProbeBudget). Lives here, not in internal/handlers, so the sqlite/postgres
// implementations of ReserveDownload can compute and atomically charge the
// per-session probe grant against files.uncounted_bytes inside the same
// transaction that takes the reservation slot — reading a separately-fetched
// uncounted_bytes snapshot and charging it later (as the handler used to)
// left a race where concurrent tokenless probes could each be granted a full
// P-byte allowance before any of them charged the shared budget.
const (
	MinProbeThresholdBytes = 1
	MaxProbeThresholdBytes = 64 * 1024
	ProbeBudgetMultiplier  = 4
)

// ProbeThreshold computes P = clamp(fileSize/16, 1, 64KiB): the number of
// tokenless bytes a single download session may deliver for free before it
// must be committed. See ADR-014 "commit policy".
func ProbeThreshold(fileSize int64) int64 {
	p := fileSize / 16
	if p < MinProbeThresholdBytes {
		p = MinProbeThresholdBytes
	}
	if p > MaxProbeThresholdBytes {
		p = MaxProbeThresholdBytes
	}
	return p
}

// ProbeBudget computes B = ProbeBudgetMultiplier * P: the cumulative
// files.uncounted_bytes a file may accumulate from granted-but-unspent (or
// spent-but-cancelled) probe allowances before new sessions stop being
// granted any free allowance at all (closes the salami-slicing variant of
// T1: a client deliberately staying just under P on every request).
func ProbeBudget(threshold int64) int64 {
	return threshold * ProbeBudgetMultiplier
}

// SessionByteLimit bounds the cumulative bytes a single, already-committed
// download session may have reserved via ReserveSessionBytes across however
// many trusted-token requests replay it — see ReserveSessionBytes. Set at
// twice the file size: generous enough that legitimate overlapping retries
// (a download manager re-requesting an already-in-flight range) don't get
// spuriously bounced to a fresh, tokenless request, but finite, so a
// committed session's token cannot be curled/replayed to redeliver the whole
// file an unbounded number of times within its idle/max-age TTL.
func SessionByteLimit(fileSize int64) int64 {
	return 2 * fileSize
}

// DownloadSession is a read-only snapshot of a download_sessions row, as
// returned by LookupDownloadSession. See ADR-014 for the full design.
type DownloadSession struct {
	FileID        int64
	Committed     bool
	Completed     bool
	BytesServed   int64
	BytesReserved int64
	CreatedAt     time.Time
	LastSeenAt    time.Time
	// CompletedAt is the zero time unless Completed is true. Set when
	// LookupDownloadSession resolves a completed session inside the T42 grace
	// window (see ResolveCompleteGrace) so callers can log/inspect how long
	// ago the download actually finished.
	CompletedAt time.Time
}

// DownloadCommitResult is the outcome of CommitDownloadSession.
type DownloadCommitResult int

const (
	// DownloadCommitCredited means this call moved the session from
	// uncommitted to committed and credited files.download_count.
	DownloadCommitCredited DownloadCommitResult = iota
	// DownloadCommitAlreadyCommitted means the session was already committed
	// by an earlier call (idempotent no-op; the counter was not touched again).
	DownloadCommitAlreadyCommitted
	// DownloadCommitSlotLost means the session row was gone (the reaper had
	// already cancelled it) and no slot was available to re-acquire. The
	// caller must not credit a download and must abort the stream rather
	// than deliver bytes past the commit threshold without a held slot.
	DownloadCommitSlotLost
)

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

	// ReserveDownload atomically checks the limit and creates a new, UNCOMMITTED
	// download_sessions row (ADR-014; supersedes the download_reservations row of
	// ADR-012). Returns (token, granted, nil) on success; the token is opaque, is
	// a bearer credential (only its SHA-256 hash is stored), and must be passed
	// back to CommitDownloadSession/CommitDownload or CancelDownload. `granted` is
	// the probe-threshold allowance (bytes) atomically charged against
	// files.uncounted_bytes in the same transaction that took the reservation —
	// callers use it directly as the session's commit threshold (see
	// internal/handlers/session_writer.go) instead of separately computing
	// ProbeThreshold against a snapshot read earlier, which would race against
	// concurrent reservations on the same file. Returns ("", 0, nil) when the file
	// is at its limit (download_count + in_flight_reservations >= max_downloads).
	// Returns ("", 0, ErrClaimCodeChanged) if the claim code changed between the
	// handler's GetByClaimCode and this call.
	//
	// Files with max_downloads = NULL or 0 bypass the database entirely and return
	// the literal token ReservationTokenUnlimited (and granted=0, unused). Callers
	// must skip Commit/Cancel for that token.
	ReserveDownload(ctx context.Context, fileID int64, expectedClaimCode string) (token string, granted int64, err error)

	// LookupDownloadSession looks up a download_sessions row by (fileID, token).
	// Returns (nil, nil) — never an error — when the token is absent, belongs to a
	// different file, has gone stale under idleTTL/maxAge, or has already been
	// completed for longer than completeGrace (see below): ADR-014 deliberately
	// gives callers no oracle to distinguish these cases from each other, so a
	// bad or spent token is always treated as a fresh, tokenless download rather
	// than surfaced as an error.
	//
	// completeGrace (T42, amending ADR-014 — see ADR-014 addendum) is the window
	// after a session's completed_at during which a trusted-token resume is
	// still allowed to resolve it, instead of unconditionally rejecting any
	// completed session (bug-hunter finding: without SOME cutoff, a
	// committed-and-fully-delivered session's token could be replayed
	// indefinitely — see CommitDownloadSession's AlreadyCommitted outcome — to
	// redeliver the whole file to anyone holding the token). This closes the
	// gap where a client pauses a download after the server has handed the last
	// byte to the kernel/network stack but before the client actually received
	// it: the session is already `completed_at` server-side, so without a grace
	// window the resume's valid token would be silently treated as unresolved
	// and the request would 410 once the file's cap is spent. completeGrace <= 0
	// disables this and restores the original "any completed session is
	// unconditionally treated as not found" behaviour. A resolved-within-grace
	// session is safe to resume: CommitDownloadSession and CompleteDownloadSession
	// are both idempotent no-ops once committed_at/completed_at are already set,
	// so nothing is double-credited or double-notified — see ReserveSessionBytes
	// for how replay volume is still bounded during the grace window.
	//
	// A non-nil, not-yet-completed (or completed-within-grace) result is not
	// itself a license to stream unconditionally: see ReserveSessionBytes, which
	// callers must use to bound how many bytes a single resolved session may
	// redeliver via replayed requests.
	LookupDownloadSession(ctx context.Context, fileID int64, token string, idleTTL, maxAge, completeGrace time.Duration) (*DownloadSession, error)

	// ReserveSessionBytes atomically charges `length` bytes against a resolved
	// (LookupDownloadSession-found) session's bytes_reserved counter, bounded by
	// `limit` (see SessionByteLimit) — the safety net behind LookupDownloadSession's
	// completed_at check: it bounds how many bytes a single committed session can
	// have in flight across concurrent or replayed requests before rejecting
	// further ones, rather than trusting an unbounded number of parallel
	// "trusted" streams. A not-yet-completed session is always eligible; a
	// completed session is eligible only while completeGrace > 0 and it is still
	// within that grace window of its own completed_at (T42) — the same bound
	// LookupDownloadSession applies, re-checked here atomically so a session
	// that crosses the grace boundary between the two calls can't sneak past it.
	// Returns (false, nil) — not an error — if the row is missing, ineligible
	// (completed outside the grace window, or grace disabled), or the charge
	// would exceed limit; the caller must treat that exactly like an unresolved
	// token (fall back to ReserveDownload). The charge is for the request's
	// whole requested range up front, before any bytes are known to have
	// actually gone out — see ReleaseSessionBytes, which callers use at finalize
	// to give back whatever portion wasn't actually sent (a paused, aborted, or
	// errored request would otherwise permanently eat into the ceiling for bytes
	// it never delivered, exhausting it well before 2x the file size' worth of
	// real replay).
	ReserveSessionBytes(ctx context.Context, fileID int64, token string, length, limit int64, completeGrace time.Duration) (bool, error)

	// ReleaseSessionBytes gives back `amount` bytes to a session's
	// bytes_reserved ceiling — called once a request that called
	// ReserveSessionBytes finishes, for the portion of its charged range it
	// didn't actually manage to send (paused, aborted, or errored partway).
	// Clamped at 0; a no-op — not an error — if the row is missing (already
	// reaped/deleted/completed) or amount <= 0. Without this, a normal
	// pause/resume sequence on a large file could exhaust the 2x-file-size
	// ceiling purely from charged-but-unsent bytes, well before the
	// recipient's one legitimate download finishes (bug-hunter finding).
	ReleaseSessionBytes(ctx context.Context, fileID int64, token string, amount int64) error

	// CommitDownloadSession marks a download_sessions row committed and, on the
	// transition from uncommitted to committed, atomically decrements
	// in_flight_reservations, increments download_count (the same guard as
	// ReserveDownload: (download_count + in_flight_reservations) < max_downloads),
	// and refunds the row's entire probe_bytes_granted back to
	// files.uncounted_bytes — once a session is credited it is a real download,
	// not an "uncounted probe", so none of its granted allowance should still
	// count against the file's probe budget. It does NOT touch
	// completed_downloads — see CompleteDownloadSession.
	//
	// Idempotent: a second call against an already-committed session returns
	// DownloadCommitAlreadyCommitted without touching the counters again.
	//
	// Reaped-mid-stream recovery: if the row is gone (the reaper's lease TTL
	// expired it), this method attempts to atomically re-acquire a slot and, on
	// success, re-inserts a committed row under the same token hash so a later
	// CompleteDownloadSession can still find it. If no slot is available it
	// returns DownloadCommitSlotLost — the caller must stop streaming rather than
	// deliver bytes without a held slot.
	CommitDownloadSession(ctx context.Context, fileID int64, token string) (DownloadCommitResult, error)

	// TouchDownloadSession renews a session's last_seen_at (the reaper's lease
	// clock — see ReapDownloadSessions) and adds bytesDelta to bytes_served. A
	// no-op (not an error) if the row doesn't exist. Callers should only call this
	// when bytesDelta > 0: a stalled connection must stop renewing the lease so
	// the reaper can eventually recover it (closes T5).
	TouchDownloadSession(ctx context.Context, fileID int64, token string, bytesDelta int64) error

	// CompleteDownloadSession marks a committed session's completed_at (guarded by
	// completed_at IS NULL) and, on the first such call, increments
	// completed_downloads. Returns first=true only on that first call — a repeat
	// call is a no-op and returns first=false. Safe to call on an uncommitted or
	// nonexistent session (returns false, nil).
	CompleteDownloadSession(ctx context.Context, fileID int64, token string) (first bool, err error)

	// CommitDownload finalises a reservation/session and credits both
	// download_count and completed_downloads in one call.
	//
	// For token == ReservationTokenUnlimited (files with no max_downloads cap) it
	// credits the counters directly — there's no download_sessions row to update.
	//
	// For any other token it is a thin backward-compatible wrapper around
	// CommitDownloadSession followed by CompleteDownloadSession, preserved because
	// under ADR-012 a single Commit call always implied a full, successful
	// delivery. New code driving the resumable-download flow (ADR-014) should call
	// CommitDownloadSession / CompleteDownloadSession directly so a mid-stream
	// commit (crossing the probe threshold) doesn't prematurely mark the download
	// "completed" before the bytes have actually finished streaming.
	//
	// Idempotent: a second call with the same token is a no-op.
	CommitDownload(ctx context.Context, fileID int64, token string) error

	// CancelDownload releases an UNCOMMITTED download_sessions row without
	// crediting a download: deletes the row, decrements in_flight_reservations,
	// and refunds (probe_bytes_granted - bytes_served) from files.uncounted_bytes
	// (clamped at 0) — the probe-budget accounting described in ADR-014
	// §"commit policy". Only the unspent portion of the grant is refunded: the
	// grant was charged in full at Reserve time, so bytes the session actually
	// served stay charged against the budget even though the download itself was
	// never credited. A no-op — not an error — if the row is missing or already
	// committed (idempotent, and safe to call after a successful
	// Commit/CommitDownloadSession).
	//
	// No-op for token == ReservationTokenUnlimited.
	CancelDownload(ctx context.Context, fileID int64, token string) error

	// ReapDownloadSessions sweeps two independent classes of stale
	// download_sessions rows, using cutoffs computed DB-side (NOT Go-side
	// time.Now().Add(-ttl) — see bug-hunter M4 in ADR-012 for why wall-clock skew
	// between app and DB makes that unsafe):
	//
	//   - uncommitted rows whose last_seen_at is older than leaseTTL: treated as
	//     abandoned (crashed process, or a probe the client never resumed).
	//     Decrements in_flight_reservations and refunds
	//     (probe_bytes_granted - bytes_served) to files.uncounted_bytes, exactly
	//     like CancelDownload, then deletes the row.
	//   - committed rows that are idle longer than idleTTL, or older than the
	//     absolute maxAge, are deleted outright with NO counter change — the
	//     download was already credited (and its probe_bytes_granted already
	//     refunded in full) at commit time, so this is just record cleanup, not
	//     a cancellation. A completed row is additionally protected until
	//     completeGrace has elapsed since its own completed_at (T42): it is
	//     never deleted by the idle/max-age rule alone while still inside its
	//     grace window, so a paused-then-resumed download can't have its
	//     session row swept out from under LookupDownloadSession's grace-window
	//     check before the client gets a chance to resume. completeGrace <= 0
	//     disables this protection and a completed row is reaped by the same
	//     idle/max-age rule as any other committed row, exactly as before T42.
	//
	// Replaces ReapStaleReservations (ADR-012); see ADR-014 for why a single TTL
	// was no longer sufficient (T5: the old 30m reservation TTL was shorter than
	// the up-to-6h transfer deadline, so the reaper could free a slot that was
	// still genuinely streaming).
	ReapDownloadSessions(ctx context.Context, leaseTTL, idleTTL, maxAge, completeGrace time.Duration) (cancelled, expired int, err error)

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
