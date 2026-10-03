package repository

import (
	"context"

	"github.com/fjmerc/safeshare/internal/models"
)

// AuditGenesisHash is the prev_hash of the first audit entry ever written.
const AuditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditSigner computes an entry's hash from all of its fields, including ID
// and PrevHash (see internal/audit).
type AuditSigner func(e *models.AuditLog) string

// AuditLogRepository stores the tamper-evident audit log (ADR-018).
type AuditLogRepository interface {
	// Append chains and inserts e atomically: holding a lock that serialises
	// every append (across processes too), it reads the current head, sets
	// e.ID to the head's id + 1 and e.PrevHash to the head's hash, sets
	// e.EntryHash = sign(e), and inserts it. Ids are therefore contiguous.
	Append(ctx context.Context, e *models.AuditLog, sign AuditSigner) error

	// List returns matching entries, newest first.
	List(ctx context.Context, filter models.AuditLogFilter) ([]models.AuditLog, error)

	// Range returns up to limit entries with id > afterID, oldest first.
	Range(ctx context.Context, afterID int64, limit int) ([]models.AuditLog, error)

	// Head returns the newest entry's id and hash (the anchor if the log is
	// empty).
	Head(ctx context.Context) (models.AuditAnchor, error)

	// Anchor returns where the chain starts: id 0 and AuditGenesisHash until
	// retention has pruned something.
	Anchor(ctx context.Context) (models.AuditAnchor, error)

	// Prune deletes the oldest entries: everything before the oldest entry
	// timestamped at or after `before` (a prefix by id, so a backdated
	// entry further along can't drag newer ones with it). Within one
	// transaction it first passes every entry to be deleted, in id order,
	// to the checker newCheck builds for the current anchor, and deletes
	// nothing if that returns an error; then it deletes them, moves the
	// anchor to the last one, and appends the event makeEvent builds for
	// that anchor, so every prune is itself recorded in the signed chain.
	// It returns how many entries were deleted; with none, nothing is
	// written.
	//
	// newCheck also gets the newest retention prune entry (nil if none), so
	// it can refuse to start from an anchor no signed prune vouches for. At
	// most maxEntries are deleted per call, keeping the lock short.
	Prune(ctx context.Context, before string, maxEntries int64,
		newCheck func(anchor models.AuditAnchor, lastPrune *models.AuditLog) (func(*models.AuditLog) error, error),
		makeEvent func(models.AuditAnchor, int64) *models.AuditLog, sign AuditSigner) (int64, error)

	// RetentionDays returns how many days entries are kept (0 = forever).
	RetentionDays(ctx context.Context) (int, error)

	// SetRetentionDays changes it.
	SetRetentionDays(ctx context.Context, days int) error
}
