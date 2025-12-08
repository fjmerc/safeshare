package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// LockRepository implements repository.LockRepository for SQLite.
// For SQLite (single-node), this uses database-based locking which is
// sufficient since all operations run on the same instance.
//
// IMPORTANT: This implementation only provides locking within a single
// application instance. For multi-node deployments, use PostgreSQL.
type LockRepository struct {
	db *sql.DB
}

// NewLockRepository creates a new SQLite lock repository.
func NewLockRepository(db *sql.DB) *LockRepository {
	return &LockRepository{db: db}
}

// TryAcquire attempts to acquire a lock without blocking.
func (r *LockRepository) TryAcquire(ctx context.Context, lockType repository.LockType, lockKey string, ttl time.Duration, ownerID string) (bool, *repository.LockInfo, error) {
	// Validate inputs
	if err := repository.ValidateLockType(lockType); err != nil {
		return false, nil, err
	}
	if err := repository.ValidateLockKey(lockKey); err != nil {
		return false, nil, err
	}
	if ownerID == "" {
		return false, nil, fmt.Errorf("owner_id cannot be empty")
	}
	if ttl <= 0 {
		return false, nil, fmt.Errorf("ttl must be positive")
	}

	// Cap TTL to prevent overflow (max 24 hours)
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	// Use IMMEDIATE transaction mode for proper locking
	tx, err := beginImmediateTx(ctx, r.db)
	if err != nil {
		return false, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Check if lock exists and is not expired
	var existingOwner string
	var existingExpiresAt string
	checkQuery := `
		SELECT owner_id, expires_at
		FROM distributed_locks
		WHERE lock_type = ? AND lock_key = ?
	`
	err = tx.QueryRowContext(ctx, checkQuery, string(lockType), lockKey).Scan(&existingOwner, &existingExpiresAt)

	if err == nil {
		// Lock exists - check if expired
		expTime, parseErr := time.Parse(time.RFC3339, existingExpiresAt)
		if parseErr != nil {
			// Invalid timestamp - treat as expired
			// Delete and continue to acquire
		} else if expTime.After(now) {
			// Lock is still valid
			if existingOwner == ownerID {
				// We already own this lock - refresh it
				return r.refreshInTransaction(ctx, tx, lockType, lockKey, ttl, ownerID, now)
			}
			// Lock held by another owner
			return false, nil, nil
		}
		// Lock expired - delete it and acquire
		deleteQuery := `DELETE FROM distributed_locks WHERE lock_type = ? AND lock_key = ?`
		if _, err := tx.ExecContext(ctx, deleteQuery, string(lockType), lockKey); err != nil {
			return false, nil, fmt.Errorf("failed to delete expired lock: %w", err)
		}
	} else if err != sql.ErrNoRows {
		return false, nil, fmt.Errorf("failed to check existing lock: %w", err)
	}

	// Insert new lock
	insertQuery := `
		INSERT INTO distributed_locks (lock_type, lock_key, owner_id, acquired_at, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err = tx.ExecContext(ctx, insertQuery,
		string(lockType),
		lockKey,
		ownerID,
		now.Format(time.RFC3339),
		expiresAt.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)
	if err != nil {
		// Unique constraint violation means another process acquired it first
		return false, nil, nil
	}

	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	lockInfo := &repository.LockInfo{
		Key:        lockKey,
		Type:       lockType,
		OwnerID:    ownerID,
		AcquiredAt: now,
		ExpiresAt:  expiresAt,
	}

	return true, lockInfo, nil
}

// refreshInTransaction refreshes a lock within an existing transaction.
func (r *LockRepository) refreshInTransaction(ctx context.Context, tx *sql.Tx, lockType repository.LockType, lockKey string, ttl time.Duration, ownerID string, now time.Time) (bool, *repository.LockInfo, error) {
	expiresAt := now.Add(ttl)

	// First, get the acquired_at within the transaction (before any changes)
	var acquiredAtStr string
	selectQuery := `SELECT acquired_at FROM distributed_locks WHERE lock_type = ? AND lock_key = ? AND owner_id = ?`
	if err := tx.QueryRowContext(ctx, selectQuery, string(lockType), lockKey, ownerID).Scan(&acquiredAtStr); err != nil {
		if err == sql.ErrNoRows {
			return false, nil, nil // Lock not held by this owner
		}
		return false, nil, fmt.Errorf("failed to get lock info: %w", err)
	}

	updateQuery := `
		UPDATE distributed_locks
		SET expires_at = ?, updated_at = ?
		WHERE lock_type = ? AND lock_key = ? AND owner_id = ?
	`
	result, err := tx.ExecContext(ctx, updateQuery,
		expiresAt.Format(time.RFC3339),
		now.Format(time.RFC3339),
		string(lockType),
		lockKey,
		ownerID,
	)
	if err != nil {
		return false, nil, fmt.Errorf("failed to refresh lock: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, nil, fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return false, nil, nil
	}

	if err := tx.Commit(); err != nil {
		return false, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Parse acquired_at that we read within the transaction
	acquiredAt, err := time.Parse(time.RFC3339, acquiredAtStr)
	if err != nil {
		// Log warning but continue with now as fallback
		acquiredAt = now
	}

	lockInfo := &repository.LockInfo{
		Key:        lockKey,
		Type:       lockType,
		OwnerID:    ownerID,
		AcquiredAt: acquiredAt,
		ExpiresAt:  expiresAt,
	}

	return true, lockInfo, nil
}

// Acquire attempts to acquire a lock with blocking/retry.
func (r *LockRepository) Acquire(ctx context.Context, lockType repository.LockType, lockKey string, ttl time.Duration, timeout time.Duration, ownerID string) (*repository.LockInfo, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}

	// Cap timeout to prevent indefinite blocking (max 5 minutes)
	if timeout > 5*time.Minute {
		timeout = 5 * time.Minute
	}

	deadline := time.Now().Add(timeout)
	retryInterval := 100 * time.Millisecond
	maxRetryInterval := 2 * time.Second

	for {
		acquired, lockInfo, err := r.TryAcquire(ctx, lockType, lockKey, ttl, ownerID)
		if err != nil {
			return nil, err
		}
		if acquired {
			return lockInfo, nil
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Check timeout
		if time.Now().After(deadline) {
			return nil, repository.ErrLockTimeout
		}

		// Add jitter (up to 50% of interval) to prevent thundering herd
		jitter := time.Duration(rand.Int63n(int64(retryInterval / 2)))
		actualWait := retryInterval + jitter

		// Wait before retrying with exponential backoff + jitter
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(actualWait):
		}

		// Increase retry interval with cap
		retryInterval = retryInterval * 2
		if retryInterval > maxRetryInterval {
			retryInterval = maxRetryInterval
		}
	}
}

// Release releases a held lock.
func (r *LockRepository) Release(ctx context.Context, lockType repository.LockType, lockKey string, ownerID string) error {
	if err := repository.ValidateLockType(lockType); err != nil {
		return err
	}
	if err := repository.ValidateLockKey(lockKey); err != nil {
		return err
	}
	if ownerID == "" {
		return fmt.Errorf("owner_id cannot be empty")
	}

	query := `
		DELETE FROM distributed_locks
		WHERE lock_type = ? AND lock_key = ? AND owner_id = ?
	`

	_, err := r.db.ExecContext(ctx, query, string(lockType), lockKey, ownerID)
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	return nil
}

// Refresh extends the TTL of a held lock.
func (r *LockRepository) Refresh(ctx context.Context, lockType repository.LockType, lockKey string, ttl time.Duration, ownerID string) error {
	if err := repository.ValidateLockType(lockType); err != nil {
		return err
	}
	if err := repository.ValidateLockKey(lockKey); err != nil {
		return err
	}
	if ownerID == "" {
		return fmt.Errorf("owner_id cannot be empty")
	}
	if ttl <= 0 {
		return fmt.Errorf("ttl must be positive")
	}

	// Cap TTL to prevent overflow
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}

	now := time.Now()
	expiresAt := now.Add(ttl)

	query := `
		UPDATE distributed_locks
		SET expires_at = ?, updated_at = ?
		WHERE lock_type = ? AND lock_key = ? AND owner_id = ?
		AND datetime(expires_at) > datetime('now')
	`

	result, err := r.db.ExecContext(ctx, query,
		expiresAt.Format(time.RFC3339),
		now.Format(time.RFC3339),
		string(lockType),
		lockKey,
		ownerID,
	)
	if err != nil {
		return fmt.Errorf("failed to refresh lock: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return repository.ErrLockNotAcquired
	}

	return nil
}

// IsHeld checks if a lock is currently held.
func (r *LockRepository) IsHeld(ctx context.Context, lockType repository.LockType, lockKey string) (bool, string, error) {
	if err := repository.ValidateLockType(lockType); err != nil {
		return false, "", err
	}
	if err := repository.ValidateLockKey(lockKey); err != nil {
		return false, "", err
	}

	query := `
		SELECT owner_id
		FROM distributed_locks
		WHERE lock_type = ? AND lock_key = ?
		AND datetime(expires_at) > datetime('now')
	`

	var ownerID string
	err := r.db.QueryRowContext(ctx, query, string(lockType), lockKey).Scan(&ownerID)

	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("failed to check lock: %w", err)
	}

	return true, ownerID, nil
}

// CleanupExpired removes expired locks from the database.
func (r *LockRepository) CleanupExpired(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM distributed_locks
		WHERE datetime(expires_at) <= datetime('now')
	`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired locks: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// GetAllLocks returns all currently held locks.
func (r *LockRepository) GetAllLocks(ctx context.Context) ([]repository.LockInfo, error) {
	query := `
		SELECT lock_type, lock_key, owner_id, acquired_at, expires_at
		FROM distributed_locks
		WHERE datetime(expires_at) > datetime('now')
		ORDER BY acquired_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query locks: %w", err)
	}
	defer rows.Close()

	var locks []repository.LockInfo
	for rows.Next() {
		var lock repository.LockInfo
		var lockType string
		var acquiredAtStr, expiresAtStr string

		if err := rows.Scan(&lockType, &lock.Key, &lock.OwnerID, &acquiredAtStr, &expiresAtStr); err != nil {
			return nil, fmt.Errorf("failed to scan lock: %w", err)
		}

		lock.Type = repository.LockType(lockType)
		lock.AcquiredAt, _ = time.Parse(time.RFC3339, acquiredAtStr)
		lock.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)

		locks = append(locks, lock)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating locks: %w", err)
	}

	return locks, nil
}

// Ensure LockRepository implements repository.LockRepository.
var _ repository.LockRepository = (*LockRepository)(nil)
