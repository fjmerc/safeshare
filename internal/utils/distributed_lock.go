// Package utils provides utility functions for SafeShare.
package utils

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// Default lock configuration values.
const (
	// DefaultLockTTL is the default time-to-live for locks.
	DefaultLockTTL = 10 * time.Minute

	// DefaultLockTimeout is the default timeout for acquiring locks.
	DefaultLockTimeout = 30 * time.Second

	// ChunkAssemblyLockTTL is the TTL for chunk assembly locks.
	// Longer than default because assembly can take time for large files.
	ChunkAssemblyLockTTL = 30 * time.Minute

	// FileDeletionLockTTL is the TTL for file deletion locks.
	FileDeletionLockTTL = 5 * time.Minute

	// CleanupLockTTL is the TTL for cleanup operation locks.
	CleanupLockTTL = 15 * time.Minute
)

var (
	// ownerID is cached for the lifetime of the process.
	ownerID     string
	ownerIDOnce sync.Once
)

// GetOwnerID returns a unique identifier for this process instance.
// Format: hostname:pid:nonce
// The nonce is a cryptographic random value to prevent owner ID guessing.
// This is used to identify lock owners for debugging and safety.
func GetOwnerID() string {
	ownerIDOnce.Do(func() {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}
		// Add cryptographic nonce to prevent owner ID prediction
		nonce := make([]byte, 8)
		if _, err := rand.Read(nonce); err != nil {
			// Fallback to less secure but still unique identifier
			nonce = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
		}
		ownerID = fmt.Sprintf("%s:%d:%s", hostname, os.Getpid(), hex.EncodeToString(nonce))
	})
	return ownerID
}

// DistributedLock provides a convenient wrapper for distributed locking operations.
type DistributedLock struct {
	repo     repository.LockRepository
	lockType repository.LockType
	lockKey  string
	ownerID  string
	ttl      time.Duration
	acquired bool
	mu       sync.Mutex
}

// NewDistributedLock creates a new distributed lock wrapper.
func NewDistributedLock(repo repository.LockRepository, lockType repository.LockType, lockKey string, ttl time.Duration) *DistributedLock {
	if ttl <= 0 {
		ttl = DefaultLockTTL
	}
	return &DistributedLock{
		repo:     repo,
		lockType: lockType,
		lockKey:  lockKey,
		ownerID:  GetOwnerID(),
		ttl:      ttl,
	}
}

// TryAcquire attempts to acquire the lock without blocking.
// Returns true if the lock was acquired, false otherwise.
func (l *DistributedLock) TryAcquire(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.repo == nil {
		// If no lock repository is configured, assume single-node and allow operation
		l.acquired = true
		return true, nil
	}

	acquired, _, err := l.repo.TryAcquire(ctx, l.lockType, l.lockKey, l.ttl, l.ownerID)
	if err != nil {
		return false, fmt.Errorf("failed to acquire lock: %w", err)
	}

	l.acquired = acquired
	return acquired, nil
}

// Acquire attempts to acquire the lock with blocking/retry up to the given timeout.
func (l *DistributedLock) Acquire(ctx context.Context, timeout time.Duration) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.repo == nil {
		// If no lock repository is configured, assume single-node and allow operation
		l.acquired = true
		return nil
	}

	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}

	_, err := l.repo.Acquire(ctx, l.lockType, l.lockKey, l.ttl, timeout, l.ownerID)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	l.acquired = true
	return nil
}

// Release releases the lock if held.
func (l *DistributedLock) Release(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.acquired {
		return nil // Nothing to release
	}

	if l.repo == nil {
		l.acquired = false
		return nil
	}

	err := l.repo.Release(ctx, l.lockType, l.lockKey, l.ownerID)
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	l.acquired = false
	return nil
}

// Refresh extends the lock TTL. Should be called periodically during long operations.
func (l *DistributedLock) Refresh(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.acquired {
		return repository.ErrLockNotAcquired
	}

	if l.repo == nil {
		return nil // Nothing to refresh in single-node mode
	}

	err := l.repo.Refresh(ctx, l.lockType, l.lockKey, l.ttl, l.ownerID)
	if err != nil {
		return fmt.Errorf("failed to refresh lock: %w", err)
	}

	return nil
}

// IsAcquired returns whether the lock is currently held.
func (l *DistributedLock) IsAcquired() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.acquired
}

// WithLock executes a function while holding the lock.
// The lock is automatically released when the function completes.
func WithLock(ctx context.Context, repo repository.LockRepository, lockType repository.LockType, lockKey string, ttl time.Duration, timeout time.Duration, fn func() error) error {
	lock := NewDistributedLock(repo, lockType, lockKey, ttl)

	if err := lock.Acquire(ctx, timeout); err != nil {
		return err
	}
	defer func() {
		if err := lock.Release(ctx); err != nil {
			slog.Warn("failed to release lock", "lock_type", lockType, "lock_key", lockKey, "error", err)
		}
	}()

	return fn()
}

// TryWithLock attempts to execute a function while holding the lock.
// If the lock cannot be acquired immediately, returns (false, nil).
// If the function is executed, returns (true, error from function).
func TryWithLock(ctx context.Context, repo repository.LockRepository, lockType repository.LockType, lockKey string, ttl time.Duration, fn func() error) (bool, error) {
	lock := NewDistributedLock(repo, lockType, lockKey, ttl)

	acquired, err := lock.TryAcquire(ctx)
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}

	defer func() {
		if err := lock.Release(ctx); err != nil {
			slog.Warn("failed to release lock", "lock_type", lockType, "lock_key", lockKey, "error", err)
		}
	}()

	return true, fn()
}

// StartLockCleanupWorker starts a background worker that periodically cleans up expired locks.
func StartLockCleanupWorker(ctx context.Context, repo repository.LockRepository, interval time.Duration) {
	if repo == nil {
		slog.Debug("lock cleanup worker disabled: no lock repository configured")
		return
	}

	if interval <= 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	slog.Info("lock cleanup worker started", "interval", interval)

	// Run immediately on start
	cleanupExpiredLocks(ctx, repo)

	for {
		select {
		case <-ctx.Done():
			slog.Info("lock cleanup worker shutting down")
			return
		case <-ticker.C:
			cleanupExpiredLocks(ctx, repo)
		}
	}
}

// cleanupExpiredLocks removes expired locks from the database.
func cleanupExpiredLocks(ctx context.Context, repo repository.LockRepository) {
	cleaned, err := repo.CleanupExpired(ctx)
	if err != nil {
		slog.Error("failed to cleanup expired locks", "error", err)
		return
	}
	if cleaned > 0 {
		slog.Info("cleaned up expired locks", "count", cleaned)
	}
}
