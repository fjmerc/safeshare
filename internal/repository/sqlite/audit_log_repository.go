package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// AuditLogRepository is the SQLite implementation of repository.AuditLogRepository.
type AuditLogRepository struct {
	db *sql.DB
}

// NewAuditLogRepository creates a new SQLite audit log repository.
func NewAuditLogRepository(db *sql.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

const auditLogColumns = `id, timestamp, event_type, action, outcome, user_id, username, ip_address,
	user_agent, resource_type, resource_id, details, prev_hash, entry_hash, key_id`

// queryer is satisfied by both *sql.DB and *sql.Tx.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func auditHead(ctx context.Context, q queryer) (models.AuditAnchor, error) {
	var head models.AuditAnchor
	err := q.QueryRowContext(ctx, `SELECT id, entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&head.ID, &head.Hash)
	if err == sql.ErrNoRows {
		return auditAnchor(ctx, q)
	}
	if err != nil {
		return head, fmt.Errorf("failed to read audit log head: %w", err)
	}
	return head, nil
}

func auditAnchor(ctx context.Context, q queryer) (models.AuditAnchor, error) {
	var a models.AuditAnchor
	err := q.QueryRowContext(ctx, `SELECT anchor_id, anchor_hash FROM audit_log_state WHERE id = 1`).Scan(&a.ID, &a.Hash)
	if err == sql.ErrNoRows {
		return models.AuditAnchor{Hash: repository.AuditGenesisHash}, nil
	}
	if err != nil {
		return a, fmt.Errorf("failed to read audit log anchor: %w", err)
	}
	return a, nil
}

// appendTx chains, signs and inserts e within tx, which must hold the
// database write lock.
func appendTx(ctx context.Context, tx *sql.Tx, e *models.AuditLog, sign repository.AuditSigner) error {
	head, err := auditHead(ctx, tx)
	if err != nil {
		return err
	}
	e.ID = head.ID + 1
	e.PrevHash = head.Hash
	e.EntryHash = sign(e)
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs (`+auditLogColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp, string(e.EventType), e.Action, string(e.Outcome), e.UserID, e.Username, e.IPAddress,
		e.UserAgent, e.ResourceType, e.ResourceID, e.Details, e.PrevHash, e.EntryHash, e.KeyID)
	if err != nil {
		return fmt.Errorf("failed to insert audit log entry: %w", err)
	}
	return nil
}

// Append implements repository.AuditLogRepository.
func (r *AuditLogRepository) Append(ctx context.Context, e *models.AuditLog, sign repository.AuditSigner) error {
	// BEGIN IMMEDIATE (the DSN's _txlock) takes the write lock up front, so
	// reading the head and inserting after it can't interleave with another
	// append, from this process or another.
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := appendTx(ctx, tx, e, sign); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit audit log entry: %w", err)
	}
	return nil
}

func scanAuditLogs(rows *sql.Rows) ([]models.AuditLog, error) {
	var out []models.AuditLog
	err := forEachAuditLog(rows, func(e *models.AuditLog) error {
		out = append(out, *e)
		return nil
	})
	return out, err
}

// forEachAuditLog scans rows one entry at a time, closing them when done.
func forEachAuditLog(rows *sql.Rows, fn func(*models.AuditLog) error) error {
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
	add := func(cond string, vals ...any) {
		where = append(where, cond)
		args = append(args, vals...)
	}
	if f.EventType != "" {
		add("event_type = ?", string(f.EventType))
	}
	if f.Outcome != "" {
		add("outcome = ?", string(f.Outcome))
	}
	if f.Action != "" {
		add("action = ?", f.Action)
	}
	if f.Username != "" {
		add("username = ?", f.Username)
	}
	if f.IPAddress != "" {
		add("ip_address = ?", f.IPAddress)
	}
	if f.ResourceType != "" {
		add("resource_type = ?", f.ResourceType)
	}
	if f.ResourceID != "" {
		add("resource_id = ?", f.ResourceID)
	}
	if f.Since != "" {
		add("timestamp >= ?", f.Since)
	}
	if f.Until != "" {
		add("timestamp < ?", f.Until)
	}
	if f.Search != "" {
		add("(instr(action, ?) > 0 OR instr(username, ?) > 0 OR instr(resource_id, ?) > 0 OR instr(details, ?) > 0)",
			f.Search, f.Search, f.Search, f.Search)
	}
	if f.BeforeID > 0 {
		add("id < ?", f.BeforeID)
	}

	query := `SELECT ` + auditLogColumns + ` FROM audit_logs`
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, clampAuditLimit(f.Limit))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit log entries: %w", err)
	}
	return scanAuditLogs(rows)
}

// Range implements repository.AuditLogRepository.
func (r *AuditLogRepository) Range(ctx context.Context, afterID int64, limit int) ([]models.AuditLog, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+auditLogColumns+` FROM audit_logs WHERE id > ? ORDER BY id ASC LIMIT ?`,
		afterID, clampAuditLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("failed to read audit log range: %w", err)
	}
	return scanAuditLogs(rows)
}

// Head implements repository.AuditLogRepository.
func (r *AuditLogRepository) Head(ctx context.Context) (models.AuditAnchor, error) {
	return auditHead(ctx, r.db)
}

// Anchor implements repository.AuditLogRepository.
func (r *AuditLogRepository) Anchor(ctx context.Context) (models.AuditAnchor, error) {
	return auditAnchor(ctx, r.db)
}

// lastPruneEntry returns the newest retention prune entry, or nil.
func lastPruneEntry(ctx context.Context, tx *sql.Tx) (*models.AuditLog, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+auditLogColumns+` FROM audit_logs
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
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	anchor, err := auditAnchor(ctx, tx)
	if err != nil {
		return 0, err
	}
	// The cut is just before the oldest entry still within retention (or
	// the newest entry, if none is).
	var cut sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(
		(SELECT MIN(id) FROM audit_logs WHERE timestamp >= ?) - 1,
		(SELECT MAX(id) FROM audit_logs))`, before).Scan(&cut)
	if err != nil {
		return 0, fmt.Errorf("failed to find audit log prune point: %w", err)
	}
	if !cut.Valid || cut.Int64 <= anchor.ID {
		return 0, nil
	}
	if maxEntries > 0 && cut.Int64 > anchor.ID+maxEntries {
		cut.Int64 = anchor.ID + maxEntries
	}

	lastPrune, err := lastPruneEntry(ctx, tx)
	if err != nil {
		return 0, err
	}
	check, err := newCheck(anchor, lastPrune)
	if err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+auditLogColumns+` FROM audit_logs WHERE id <= ? ORDER BY id ASC`, cut.Int64)
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
	if last.ID != cut.Int64 {
		return 0, fmt.Errorf("refusing to prune: entries up to %d are not all present", cut.Int64)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM audit_logs WHERE id <= ?`, last.ID)
	if err != nil {
		return 0, fmt.Errorf("failed to prune audit log: %w", err)
	}
	deleted, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `UPDATE audit_log_state SET anchor_id = ?, anchor_hash = ? WHERE id = 1`, last.ID, last.Hash); err != nil {
		return 0, fmt.Errorf("failed to move audit log anchor: %w", err)
	}
	// The prune itself goes into the chain. If it removed every entry, the
	// head is the anchor just written.
	if err := appendTx(ctx, tx, makeEvent(last, deleted), sign); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit audit log prune: %w", err)
	}
	return deleted, nil
}

// RetentionDays implements repository.AuditLogRepository.
func (r *AuditLogRepository) RetentionDays(ctx context.Context) (int, error) {
	var days int
	err := r.db.QueryRowContext(ctx, `SELECT retention_days FROM audit_log_state WHERE id = 1`).Scan(&days)
	if err != nil {
		return 0, fmt.Errorf("failed to read audit log retention: %w", err)
	}
	return days, nil
}

// SetRetentionDays implements repository.AuditLogRepository.
func (r *AuditLogRepository) SetRetentionDays(ctx context.Context, days int) error {
	if days < 0 {
		return fmt.Errorf("retention days cannot be negative")
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE audit_log_state SET retention_days = ? WHERE id = 1`, days); err != nil {
		return fmt.Errorf("failed to set audit log retention: %w", err)
	}
	return nil
}
