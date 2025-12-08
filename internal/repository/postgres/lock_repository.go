package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/repository"
)

// LockRepository implements repository.LockRepository for PostgreSQL.
// This implementation uses PostgreSQL advisory locks (pg_advisory_lock) for
// true distributed locking across multiple application instances.
//
// Advisory locks are:
// - Fast (no disk I/O)
// - Automatically released on connection close
// - Safe for distributed systems
//
// We also maintain a distributed_locks table for:
// - Visibility into held locks (debugging/monitoring)
// - TTL-based expiration (safety net)
// - Lock metadata storage
type LockRepository struct {
	pool *Pool
}

// NewLockRepository creates a new PostgreSQL lock repository.
func NewLockRepository(pool *Pool) *LockRepository {
	return &LockRepository{pool: pool}
}

// lockKeyToInt32Pair converts a lock type and key to a pair of int32 values for advisory locks.
// PostgreSQL advisory locks support pg_advisory_lock(int, int) which gives 64 bits of key space.
// Using SHA-256 provides strong collision resistance.
func lockKeyToInt32Pair(lockType repository.LockType, lockKey string) (int32, int32) {
	h := sha256.Sum256([]byte(string(lockType) + ":" + lockKey))
	id1 := int32(binary.BigEndian.Uint32(h[0:4]))
	id2 := int32(binary.BigEndian.Uint32(h[4:8]))
	return id1, id2
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
	advisoryLockID1, advisoryLockID2 := lockKeyToInt32Pair(lockType, lockKey)

	// Try to acquire PostgreSQL session-level advisory lock (non-blocking)
	// Session-level locks persist until explicitly released or connection closes
	var acquired bool
	err := r.pool.QueryRow(ctx, "SELECT pg_try_advisory_lock($1, $2)", advisoryLockID1, advisoryLockID2).Scan(&acquired)
	if err != nil {
		return false, nil, fmt.Errorf("failed to try advisory lock: %w", err)
	}

	if !acquired {
		// Lock is held by another connection
		return false, nil, nil
	}

	// Advisory lock acquired - now update or insert into distributed_locks table
	// Use a transaction for the table operations
	tx, err := r.pool.BeginTx(ctx, TxOptions())
	if err != nil {
		// Release advisory lock on error
		r.pool.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", advisoryLockID1, advisoryLockID2)
		return false, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Clean up any expired entries for this key
	_, err = tx.Exec(ctx, `
		DELETE FROM distributed_locks
		WHERE lock_type = $1 AND lock_key = $2 AND expires_at <= NOW()
	`, string(lockType), lockKey)
	if err != nil {
		r.pool.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", advisoryLockID1, advisoryLockID2)
		return false, nil, fmt.Errorf("failed to cleanup expired lock: %w", err)
	}

	// Check if there's an existing valid lock
	var existingOwner string
	var existingAcquiredAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT owner_id, acquired_at
		FROM distributed_locks
		WHERE lock_type = $1 AND lock_key = $2 AND expires_at > NOW()
	`, string(lockType), lockKey).Scan(&existingOwner, &existingAcquiredAt)

	if err == nil {
		// Lock record exists
		if existingOwner == ownerID {
			// We already own this lock - refresh it
			_, err = tx.Exec(ctx, `
				UPDATE distributed_locks
				SET expires_at = $1, updated_at = NOW()
				WHERE lock_type = $2 AND lock_key = $3 AND owner_id = $4
			`, expiresAt, string(lockType), lockKey, ownerID)
			if err != nil {
				r.pool.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", advisoryLockID1, advisoryLockID2)
				return false, nil, fmt.Errorf("failed to refresh lock: %w", err)
			}

			if err := tx.Commit(ctx); err != nil {
				r.pool.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", advisoryLockID1, advisoryLockID2)
				return false, nil, fmt.Errorf("failed to commit transaction: %w", err)
			}

			return true, &repository.LockInfo{
				Key:        lockKey,
				Type:       lockType,
				OwnerID:    ownerID,
				AcquiredAt: existingAcquiredAt,
				ExpiresAt:  expiresAt,
			}, nil
		}
		// Different owner in table but we have advisory lock - stale record
		// This shouldn't happen normally, but handle it by taking ownership
	} else if err != pgx.ErrNoRows {
		r.pool.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", advisoryLockID1, advisoryLockID2)
		return false, nil, fmt.Errorf("failed to check existing lock: %w", err)
	}

	// No existing lock or stale record - insert/update
	_, err = tx.Exec(ctx, `
		INSERT INTO distributed_locks (lock_type, lock_key, owner_id, acquired_at, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (lock_type, lock_key) DO UPDATE
		SET owner_id = EXCLUDED.owner_id,
		    acquired_at = EXCLUDED.acquired_at,
		    expires_at = EXCLUDED.expires_at,
		    updated_at = NOW()
	`, string(lockType), lockKey, ownerID, now, expiresAt)
	if err != nil {
		r.pool.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", advisoryLockID1, advisoryLockID2)
		return false, nil, fmt.Errorf("failed to insert lock: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		r.pool.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", advisoryLockID1, advisoryLockID2)
		return false, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return true, &repository.LockInfo{
		Key:        lockKey,
		Type:       lockType,
		OwnerID:    ownerID,
		AcquiredAt: now,
		ExpiresAt:  expiresAt,
	}, nil
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

	advisoryLockID1, advisoryLockID2 := lockKeyToInt32Pair(lockType, lockKey)

	// Delete from distributed_locks table
	_, err := r.pool.Exec(ctx, `
		DELETE FROM distributed_locks
		WHERE lock_type = $1 AND lock_key = $2 AND owner_id = $3
	`, string(lockType), lockKey, ownerID)
	if err != nil {
		return fmt.Errorf("failed to release lock record: %w", err)
	}

	// Release the PostgreSQL advisory lock
	// Note: pg_advisory_unlock returns false if lock wasn't held, which is fine
	_, err = r.pool.Exec(ctx, "SELECT pg_advisory_unlock($1, $2)", advisoryLockID1, advisoryLockID2)
	if err != nil {
		return fmt.Errorf("failed to release advisory lock: %w", err)
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

	expiresAt := time.Now().Add(ttl)

	result, err := r.pool.Exec(ctx, `
		UPDATE distributed_locks
		SET expires_at = $1, updated_at = NOW()
		WHERE lock_type = $2 AND lock_key = $3 AND owner_id = $4
		AND expires_at > NOW()
	`, expiresAt, string(lockType), lockKey, ownerID)
	if err != nil {
		return fmt.Errorf("failed to refresh lock: %w", err)
	}

	if result.RowsAffected() == 0 {
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

	var ownerID string
	err := r.pool.QueryRow(ctx, `
		SELECT owner_id
		FROM distributed_locks
		WHERE lock_type = $1 AND lock_key = $2
		AND expires_at > NOW()
	`, string(lockType), lockKey).Scan(&ownerID)

	if err == pgx.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("failed to check lock: %w", err)
	}

	return true, ownerID, nil
}

// CleanupExpired removes expired locks from the database.
func (r *LockRepository) CleanupExpired(ctx context.Context) (int64, error) {
	result, err := r.pool.Exec(ctx, `
		DELETE FROM distributed_locks
		WHERE expires_at <= NOW()
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired locks: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetAllLocks returns all currently held locks.
func (r *LockRepository) GetAllLocks(ctx context.Context) ([]repository.LockInfo, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT lock_type, lock_key, owner_id, acquired_at, expires_at
		FROM distributed_locks
		WHERE expires_at > NOW()
		ORDER BY acquired_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query locks: %w", err)
	}
	defer rows.Close()

	var locks []repository.LockInfo
	for rows.Next() {
		var lock repository.LockInfo
		var lockType string
		var acquiredAt sql.NullTime
		var expiresAt sql.NullTime

		if err := rows.Scan(&lockType, &lock.Key, &lock.OwnerID, &acquiredAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("failed to scan lock: %w", err)
		}

		lock.Type = repository.LockType(lockType)
		if acquiredAt.Valid {
			lock.AcquiredAt = acquiredAt.Time
		}
		if expiresAt.Valid {
			lock.ExpiresAt = expiresAt.Time
		}

		locks = append(locks, lock)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating locks: %w", err)
	}

	return locks, nil
}

// Ensure LockRepository implements repository.LockRepository.
var _ repository.LockRepository = (*LockRepository)(nil)
