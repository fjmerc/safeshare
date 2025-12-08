// Package repository provides interfaces for database operations.
package repository

import (
	"context"
	"errors"
	"time"
)

// Common lock errors.
var (
	// ErrLockNotAcquired indicates the lock could not be acquired (already held).
	ErrLockNotAcquired = errors.New("lock not acquired")

	// ErrLockTimeout indicates the lock acquisition timed out.
	ErrLockTimeout = errors.New("lock timeout")

	// ErrInvalidLockKey indicates the lock key is invalid (empty or too long).
	ErrInvalidLockKey = errors.New("invalid lock key")

	// ErrLockExpired indicates the lock has expired.
	ErrLockExpired = errors.New("lock expired")
)

// LockType represents the type of distributed lock.
type LockType string

// Lock types for different operations.
const (
	// LockTypeChunkAssembly is used when assembling chunks into a final file.
	LockTypeChunkAssembly LockType = "chunk_assembly"

	// LockTypeFileDeletion is used when deleting files from storage.
	LockTypeFileDeletion LockType = "file_deletion"

	// LockTypeExpiredCleanup is used when cleaning up expired files.
	LockTypeExpiredCleanup LockType = "expired_cleanup"

	// LockTypeOrphanCleanup is used when cleaning up orphaned files.
	LockTypeOrphanCleanup LockType = "orphan_cleanup"

	// LockTypeBackup is used during backup operations.
	LockTypeBackup LockType = "backup"
)

// LockInfo contains information about an acquired lock.
type LockInfo struct {
	// Key is the unique identifier for the lock.
	Key string `json:"key"`

	// Type is the lock type.
	Type LockType `json:"type"`

	// OwnerID identifies the lock owner (hostname:pid or instance ID).
	OwnerID string `json:"owner_id"`

	// AcquiredAt is when the lock was acquired.
	AcquiredAt time.Time `json:"acquired_at"`

	// ExpiresAt is when the lock will expire (for safety).
	ExpiresAt time.Time `json:"expires_at"`

	// Metadata contains optional metadata about the lock.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// LockRepository defines the interface for distributed locking operations.
// Implementations must be safe for concurrent use from multiple goroutines
// and multiple application instances.
type LockRepository interface {
	// TryAcquire attempts to acquire a lock without blocking.
	// Returns (true, LockInfo, nil) if lock was acquired.
	// Returns (false, nil, nil) if lock is held by another process.
	// Returns (false, nil, error) on unexpected errors.
	//
	// The lockKey must be unique for the resource being locked.
	// The ttl specifies how long the lock is held before auto-expiring.
	// The ownerID identifies the lock holder (for debugging and stale lock detection).
	TryAcquire(ctx context.Context, lockType LockType, lockKey string, ttl time.Duration, ownerID string) (bool, *LockInfo, error)

	// Acquire attempts to acquire a lock with blocking/retry.
	// Returns (LockInfo, nil) if lock was acquired.
	// Returns (nil, ErrLockTimeout) if lock could not be acquired within timeout.
	// Returns (nil, error) on unexpected errors.
	//
	// The implementation should retry periodically until timeout.
	Acquire(ctx context.Context, lockType LockType, lockKey string, ttl time.Duration, timeout time.Duration, ownerID string) (*LockInfo, error)

	// Release releases a held lock.
	// Only the lock owner should be able to release the lock.
	// Returns nil if lock was released successfully or was not held.
	// Returns error on unexpected errors.
	Release(ctx context.Context, lockType LockType, lockKey string, ownerID string) error

	// Refresh extends the TTL of a held lock.
	// This is used to keep long-running operations from losing their lock.
	// Returns nil if refresh was successful.
	// Returns ErrLockNotAcquired if the lock is not held by this owner.
	Refresh(ctx context.Context, lockType LockType, lockKey string, ttl time.Duration, ownerID string) error

	// IsHeld checks if a lock is currently held.
	// Returns (true, ownerID) if locked.
	// Returns (false, "") if not locked.
	IsHeld(ctx context.Context, lockType LockType, lockKey string) (bool, string, error)

	// CleanupExpired removes expired locks from the database.
	// This is a maintenance operation that should be called periodically.
	// Returns the number of expired locks cleaned up.
	CleanupExpired(ctx context.Context) (int64, error)

	// GetAllLocks returns all currently held locks (for debugging/monitoring).
	GetAllLocks(ctx context.Context) ([]LockInfo, error)
}

// ValidLockTypes is a set of valid lock types for validation.
var ValidLockTypes = map[LockType]bool{
	LockTypeChunkAssembly:  true,
	LockTypeFileDeletion:   true,
	LockTypeExpiredCleanup: true,
	LockTypeOrphanCleanup:  true,
	LockTypeBackup:         true,
}

// ValidateLockType validates that the lock type is valid.
func ValidateLockType(lockType LockType) error {
	if !ValidLockTypes[lockType] {
		return errors.New("invalid lock type")
	}
	return nil
}

// ValidateLockKey validates that the lock key is valid.
func ValidateLockKey(key string) error {
	if key == "" {
		return ErrInvalidLockKey
	}
	if len(key) > 255 {
		return ErrInvalidLockKey
	}
	return nil
}
