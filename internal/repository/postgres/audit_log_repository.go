package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// AuditLogRepository is the PostgreSQL implementation of repository.AuditLogRepository.
type AuditLogRepository struct {
	pool *Pool
}

// NewAuditLogRepository creates a new PostgreSQL audit log repository.
func NewAuditLogRepository(pool *Pool) *AuditLogRepository {
	return &AuditLogRepository{pool: pool}
}

// auditAppendLockKey is the pg_advisory_xact_lock key serialising appends
// across every connection and instance ("audit" in ASCII).
const auditAppendLockKey int64 = 0x6175646974

const auditLogColumns = `id, timestamp, event_type, action, outcome, user_id, username, ip_address,
	user_agent, resource_type, resource_id, details, prev_hash, entry_hash, key_id`

// pgQueryer is satisfied by both *Pool and pgx.Tx.
type pgQueryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func auditHead(ctx context.Context, q pgQueryer) (models.AuditAnchor, error) {
	var head models.AuditAnchor
	err := q.QueryRow(ctx, `SELECT id, entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&head.ID, &head.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return auditAnchor(ctx, q)
	}
	if err != nil {
		return head, fmt.Errorf("failed to read audit log head: %w", err)
	}
	return head, nil
}

func auditAnchor(ctx context.Context, q pgQueryer) (models.AuditAnchor, error) {
	var a models.AuditAnchor
	err := q.QueryRow(ctx, `SELECT anchor_id, anchor_hash FROM audit_log_state WHERE id = 1`).Scan(&a.ID, &a.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.AuditAnchor{Hash: repository.AuditGenesisHash}, nil
	}
	if err != nil {
		return a, fmt.Errorf("failed to read audit log anchor: %w", err)
	}
	return a, nil
}

// beginAuditTx starts a transaction holding the append lock. A row lock on
// the newest entry wouldn't do: it can't stop another transaction from
// inserting a new newest entry.
func (r *AuditLogRepository) beginAuditTx(ctx context.Context) (pgx.Tx, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	// Don't queue indefinitely behind a stalled lock holder: an audit write
	// that can't get in within a few seconds fails (and is counted)
	// rather than tying up a pooled connection.
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("failed to set audit lock timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditAppendLockKey); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("failed to lock audit log: %w", err)
	}
	return tx, nil
}

func appendAuditTx(ctx context.Context, tx pgx.Tx, e *models.AuditLog, sign repository.AuditSigner) error {
	head, err := auditHead(ctx, tx)
	if err != nil {
		return err
	}
	e.ID = head.ID + 1
	e.PrevHash = head.Hash
	e.EntryHash = sign(e)
	_, err = tx.Exec(ctx, `INSERT INTO audit_logs (`+auditLogColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		e.ID, e.Timestamp, string(e.EventType), e.Action, string(e.Outcome), e.UserID, e.Username, e.IPAddress,
		e.UserAgent, e.ResourceType, e.ResourceID, e.Details, e.PrevHash, e.EntryHash, e.KeyID)
	if err != nil {
		return fmt.Errorf("failed to insert audit log entry: %w", err)
	}
	return nil
}

// Append implements repository.AuditLogRepository.
func (r *AuditLogRepository) Append(ctx context.Context, e *models.AuditLog, sign repository.AuditSigner) error {
	tx, err := r.beginAuditTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit

	if err := appendAuditTx(ctx, tx, e, sign); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit audit log entry: %w", err)
	}
	return nil
}

func scanAuditLogs(rows pgx.Rows) ([]models.AuditLog, error) {
	var out []models.AuditLog
	err := forEachAuditLog(rows, func(e *models.AuditLog) error {
		out = append(out, *e)
		return nil
	})
	return out, err
}

// forEachAuditLog scans rows one entry at a time, closing them when done.
func forEachAuditLog(rows pgx.Rows, fn func(*models.AuditLog) error) error {
	defer rows.Close()
	for rows.Next() {
		var e models.AuditLog
		var eventType, outcome string
		if err := rows.Scan(&e.ID, &e.Timestamp, &eventType, &e.Action, &outcome, &e.UserID, &e.Username,
			&e.IPAddress, &e.UserAgent, &e.ResourceType, &e.ResourceID, &e.Details, &e.PrevHash, &e.EntryHash, &e.KeyID); err != nil {
			return fmt.Errorf("failed to scan audit log entry: %w", err)
		}
		e.EventType = models.AuditEventType(eventType)
		e.Outcome = models.AuditOutcome(outcome)
		if err := fn(&e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// clampAuditLimit applies the default (50) and maximum (1000) page size.
func clampAuditLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

// List implements repository.AuditLogRepository.
func (r *AuditLogRepository) List(ctx context.Context, f models.AuditLogFilter) ([]models.AuditLog, error) {
	var where []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.EventType != "" {
		add("event_type = $%d", string(f.EventType))
	}
	if f.Outcome != "" {
		add("outcome = $%d", string(f.Outcome))
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.Username != "" {
		add("username = $%d", f.Username)
	}
	if f.IPAddress != "" {
		add("ip_address = $%d", f.IPAddress)
	}
	if f.ResourceType != "" {
		add("resource_type = $%d", f.ResourceType)
	}
	if f.ResourceID != "" {
		add("resource_id = $%d", f.ResourceID)
	}
	if f.Since != "" {
		add("timestamp >= $%d", f.Since)
	}
	if f.Until != "" {
		add("timestamp < $%d", f.Until)
	}
	if f.Search != "" {
		add("(strpos(action, $%[1]d) > 0 OR strpos(username, $%[1]d) > 0 OR strpos(resource_id, $%[1]d) > 0 OR strpos(details, $%[1]d) > 0)", f.Search)
	}
	if f.BeforeID > 0 {
		add("id < $%d", f.BeforeID)
	}

	query := `SELECT ` + auditLogColumns + ` FROM audit_logs`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	args = append(args, clampAuditLimit(f.Limit))
	query += fmt.Sprintf(` ORDER BY id DESC LIMIT $%d`, len(args))

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit log entries: %w", err)
	}
	return scanAuditLogs(rows)
}

// Range implements repository.AuditLogRepository.
func (r *AuditLogRepository) Range(ctx context.Context, afterID int64, limit int) ([]models.AuditLog, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+auditLogColumns+` FROM audit_logs WHERE id > $1 ORDER BY id ASC LIMIT $2`,
		afterID, clampAuditLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("failed to read audit log range: %w", err)
	}
	return scanAuditLogs(rows)
}

// Head implements repository.AuditLogRepository.
func (r *AuditLogRepository) Head(ctx context.Context) (models.AuditAnchor, error) {
	return auditHead(ctx, r.pool)
}

// Anchor implements repository.AuditLogRepository.
func (r *AuditLogRepository) Anchor(ctx context.Context) (models.AuditAnchor, error) {
	return auditAnchor(ctx, r.pool)
}

// lastPruneEntry returns the newest retention prune entry, or nil.
func lastPruneEntry(ctx context.Context, tx pgx.Tx) (*models.AuditLog, error) {
	rows, err := tx.Query(ctx, `SELECT `+auditLogColumns+` FROM audit_logs
		WHERE event_type = 'SYSTEM' AND action = 'retention_prune' ORDER BY id DESC LIMIT 1`)
	if err != nil {
		return nil, fmt.Errorf("failed to read last retention prune: %w", err)
	}
	entries, err := scanAuditLogs(rows)
	if err != nil || len(entries) == 0 {
		return nil, err
	}
	return &entries[0], nil
}

// Prune implements repository.AuditLogRepository.
func (r *AuditLogRepository) Prune(ctx context.Context, before string, maxEntries int64,
	newCheck func(models.AuditAnchor, *models.AuditLog) (func(*models.AuditLog) error, error),
	makeEvent func(models.AuditAnchor, int64) *models.AuditLog, sign repository.AuditSigner) (int64, error) {
	tx, err := r.beginAuditTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	anchor, err := auditAnchor(ctx, tx)
	if err != nil {
		return 0, err
	}
	// The cut is just before the oldest entry still within retention (or
	// the newest entry, if none is).
	var cut *int64
	err = tx.QueryRow(ctx, `SELECT COALESCE(
		(SELECT MIN(id) FROM audit_logs WHERE timestamp >= $1) - 1,
		(SELECT MAX(id) FROM audit_logs))`, before).Scan(&cut)
	if err != nil {
		return 0, fmt.Errorf("failed to find audit log prune point: %w", err)
	}
	if cut == nil || *cut <= anchor.ID {
		return 0, nil
	}
	if maxEntries > 0 && *cut > anchor.ID+maxEntries {
		limited := anchor.ID + maxEntries
		cut = &limited
	}

	lastPrune, err := lastPruneEntry(ctx, tx)
	if err != nil {
		return 0, err
	}
	check, err := newCheck(anchor, lastPrune)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `SELECT `+auditLogColumns+` FROM audit_logs WHERE id <= $1 ORDER BY id ASC`, *cut)
	if err != nil {
		return 0, fmt.Errorf("failed to read entries to prune: %w", err)
	}
	// Streamed, not loaded: shortening retention on a large log can make
	// one prune cover many entries.
	var last models.AuditAnchor
	err = forEachAuditLog(rows, func(e *models.AuditLog) error {
		if err := check(e); err != nil {
			return err
		}
		last = models.AuditAnchor{ID: e.ID, Hash: e.EntryHash}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if last.ID != *cut {
		return 0, fmt.Errorf("refusing to prune: entries up to %d are not all present", *cut)
	}

	tag, err := tx.Exec(ctx, `DELETE FROM audit_logs WHERE id <= $1`, last.ID)
	if err != nil {
		return 0, fmt.Errorf("failed to prune audit log: %w", err)
	}
	deleted := tag.RowsAffected()
	if _, err := tx.Exec(ctx, `UPDATE audit_log_state SET anchor_id = $1, anchor_hash = $2 WHERE id = 1`, last.ID, last.Hash); err != nil {
		return 0, fmt.Errorf("failed to move audit log anchor: %w", err)
	}
	if err := appendAuditTx(ctx, tx, makeEvent(last, deleted), sign); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit audit log prune: %w", err)
	}
	return deleted, nil
}

// RetentionDays implements repository.AuditLogRepository.
func (r *AuditLogRepository) RetentionDays(ctx context.Context) (int, error) {
	var days int
	if err := r.pool.QueryRow(ctx, `SELECT retention_days FROM audit_log_state WHERE id = 1`).Scan(&days); err != nil {
		return 0, fmt.Errorf("failed to read audit log retention: %w", err)
	}
	return days, nil
}

// SetRetentionDays implements repository.AuditLogRepository.
func (r *AuditLogRepository) SetRetentionDays(ctx context.Context, days int) error {
	if days < 0 {
		return fmt.Errorf("retention days cannot be negative")
	}
	if _, err := r.pool.Exec(ctx, `UPDATE audit_log_state SET retention_days = $1 WHERE id = 1`, days); err != nil {
		return fmt.Errorf("failed to set audit log retention: %w", err)
	}
	return nil
}
