package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	_ "github.com/mattn/go-sqlite3"
)

// setupLockTestDB creates a new in-memory SQLite database for testing locks.
func setupLockTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	// Create distributed_locks table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS distributed_locks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			lock_type TEXT NOT NULL,
			lock_key TEXT NOT NULL,
			owner_id TEXT NOT NULL,
			acquired_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT,
			UNIQUE(lock_type, lock_key)
		)
	`)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	return db
}

func TestLockRepository_TryAcquire(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Test successful acquisition
	acquired, lockInfo, err := repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "upload-123", 5*time.Minute, "owner-1")
	if err != nil {
		t.Fatalf("TryAcquire failed: %v", err)
	}
	if !acquired {
		t.Error("expected lock to be acquired")
	}
	if lockInfo == nil {
		t.Fatal("expected lock info")
	}
	if lockInfo.Key != "upload-123" {
		t.Errorf("expected key 'upload-123', got '%s'", lockInfo.Key)
	}
	if lockInfo.Type != repository.LockTypeChunkAssembly {
		t.Errorf("expected type 'chunk_assembly', got '%s'", lockInfo.Type)
	}
	if lockInfo.OwnerID != "owner-1" {
		t.Errorf("expected owner 'owner-1', got '%s'", lockInfo.OwnerID)
	}

	// Test that same owner can re-acquire (refresh)
	acquired, _, err = repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "upload-123", 5*time.Minute, "owner-1")
	if err != nil {
		t.Fatalf("TryAcquire (same owner) failed: %v", err)
	}
	if !acquired {
		t.Error("expected same owner to re-acquire lock")
	}

	// Test that different owner cannot acquire
	acquired, _, err = repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "upload-123", 5*time.Minute, "owner-2")
	if err != nil {
		t.Fatalf("TryAcquire (different owner) failed: %v", err)
	}
	if acquired {
		t.Error("expected different owner to fail acquiring lock")
	}
}

func TestLockRepository_TryAcquire_ExpiredLock(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Insert an expired lock directly
	now := time.Now()
	expiredTime := now.Add(-1 * time.Hour)
	_, err := db.Exec(`
		INSERT INTO distributed_locks (lock_type, lock_key, owner_id, acquired_at, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, string(repository.LockTypeChunkAssembly), "upload-expired", "old-owner",
		now.Add(-2*time.Hour).Format(time.RFC3339),
		expiredTime.Format(time.RFC3339),
		now.Add(-2*time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to insert expired lock: %v", err)
	}

	// New owner should be able to acquire expired lock
	acquired, lockInfo, err := repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "upload-expired", 5*time.Minute, "new-owner")
	if err != nil {
		t.Fatalf("TryAcquire failed: %v", err)
	}
	if !acquired {
		t.Error("expected to acquire expired lock")
	}
	if lockInfo.OwnerID != "new-owner" {
		t.Errorf("expected owner 'new-owner', got '%s'", lockInfo.OwnerID)
	}
}

func TestLockRepository_Release(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Acquire a lock
	acquired, _, err := repo.TryAcquire(ctx, repository.LockTypeFileDeletion, "file-456", 5*time.Minute, "owner-1")
	if err != nil || !acquired {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// Release the lock
	err = repo.Release(ctx, repository.LockTypeFileDeletion, "file-456", "owner-1")
	if err != nil {
		t.Fatalf("Release failed: %v", err)
	}

	// Verify lock is released
	isHeld, _, err := repo.IsHeld(ctx, repository.LockTypeFileDeletion, "file-456")
	if err != nil {
		t.Fatalf("IsHeld failed: %v", err)
	}
	if isHeld {
		t.Error("expected lock to be released")
	}

	// Different owner can now acquire
	acquired, _, err = repo.TryAcquire(ctx, repository.LockTypeFileDeletion, "file-456", 5*time.Minute, "owner-2")
	if err != nil {
		t.Fatalf("TryAcquire after release failed: %v", err)
	}
	if !acquired {
		t.Error("expected to acquire released lock")
	}
}

func TestLockRepository_Release_WrongOwner(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Acquire a lock
	acquired, _, err := repo.TryAcquire(ctx, repository.LockTypeFileDeletion, "file-789", 5*time.Minute, "owner-1")
	if err != nil || !acquired {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// Try to release with wrong owner
	err = repo.Release(ctx, repository.LockTypeFileDeletion, "file-789", "wrong-owner")
	if err != nil {
		t.Fatalf("Release with wrong owner should not error: %v", err)
	}

	// Verify lock is still held by original owner
	isHeld, ownerID, err := repo.IsHeld(ctx, repository.LockTypeFileDeletion, "file-789")
	if err != nil {
		t.Fatalf("IsHeld failed: %v", err)
	}
	if !isHeld {
		t.Error("expected lock to still be held")
	}
	if ownerID != "owner-1" {
		t.Errorf("expected owner 'owner-1', got '%s'", ownerID)
	}
}

func TestLockRepository_Refresh(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Acquire a lock with short TTL
	acquired, lockInfo, err := repo.TryAcquire(ctx, repository.LockTypeBackup, "backup-1", 1*time.Minute, "owner-1")
	if err != nil || !acquired {
		t.Fatalf("failed to acquire lock: %v", err)
	}
	originalExpiry := lockInfo.ExpiresAt

	// Small delay to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Refresh with longer TTL
	err = repo.Refresh(ctx, repository.LockTypeBackup, "backup-1", 10*time.Minute, "owner-1")
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// Verify expiry was extended
	var expiresAtStr string
	err = db.QueryRow("SELECT expires_at FROM distributed_locks WHERE lock_type = ? AND lock_key = ?",
		string(repository.LockTypeBackup), "backup-1").Scan(&expiresAtStr)
	if err != nil {
		t.Fatalf("failed to query lock: %v", err)
	}

	newExpiry, _ := time.Parse(time.RFC3339, expiresAtStr)
	if !newExpiry.After(originalExpiry) {
		t.Error("expected expiry to be extended")
	}
}

func TestLockRepository_Refresh_NotOwner(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Acquire a lock
	acquired, _, err := repo.TryAcquire(ctx, repository.LockTypeBackup, "backup-2", 5*time.Minute, "owner-1")
	if err != nil || !acquired {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// Try to refresh with wrong owner
	err = repo.Refresh(ctx, repository.LockTypeBackup, "backup-2", 10*time.Minute, "wrong-owner")
	if err != repository.ErrLockNotAcquired {
		t.Errorf("expected ErrLockNotAcquired, got: %v", err)
	}
}

func TestLockRepository_IsHeld(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Check non-existent lock
	isHeld, ownerID, err := repo.IsHeld(ctx, repository.LockTypeExpiredCleanup, "cleanup-1")
	if err != nil {
		t.Fatalf("IsHeld failed: %v", err)
	}
	if isHeld {
		t.Error("expected non-existent lock to not be held")
	}
	if ownerID != "" {
		t.Errorf("expected empty owner, got '%s'", ownerID)
	}

	// Acquire lock
	acquired, _, err := repo.TryAcquire(ctx, repository.LockTypeExpiredCleanup, "cleanup-1", 5*time.Minute, "owner-1")
	if err != nil || !acquired {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// Check held lock
	isHeld, ownerID, err = repo.IsHeld(ctx, repository.LockTypeExpiredCleanup, "cleanup-1")
	if err != nil {
		t.Fatalf("IsHeld failed: %v", err)
	}
	if !isHeld {
		t.Error("expected lock to be held")
	}
	if ownerID != "owner-1" {
		t.Errorf("expected owner 'owner-1', got '%s'", ownerID)
	}
}

func TestLockRepository_CleanupExpired(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Insert some expired locks directly
	now := time.Now()
	expiredTime := now.Add(-1 * time.Hour)

	for i := 0; i < 5; i++ {
		_, err := db.Exec(`
			INSERT INTO distributed_locks (lock_type, lock_key, owner_id, acquired_at, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, string(repository.LockTypeChunkAssembly), "expired-"+string(rune('a'+i)), "owner",
			now.Add(-2*time.Hour).Format(time.RFC3339),
			expiredTime.Format(time.RFC3339),
			now.Add(-2*time.Hour).Format(time.RFC3339))
		if err != nil {
			t.Fatalf("failed to insert expired lock: %v", err)
		}
	}

	// Also add a valid lock
	_, _, err := repo.TryAcquire(ctx, repository.LockTypeFileDeletion, "valid-lock", 5*time.Minute, "owner")
	if err != nil {
		t.Fatalf("failed to acquire valid lock: %v", err)
	}

	// Clean up expired
	cleaned, err := repo.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired failed: %v", err)
	}
	if cleaned != 5 {
		t.Errorf("expected 5 locks cleaned up, got %d", cleaned)
	}

	// Verify valid lock still exists
	isHeld, _, err := repo.IsHeld(ctx, repository.LockTypeFileDeletion, "valid-lock")
	if err != nil {
		t.Fatalf("IsHeld failed: %v", err)
	}
	if !isHeld {
		t.Error("expected valid lock to still be held")
	}
}

func TestLockRepository_GetAllLocks(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Initially no locks
	locks, err := repo.GetAllLocks(ctx)
	if err != nil {
		t.Fatalf("GetAllLocks failed: %v", err)
	}
	if len(locks) != 0 {
		t.Errorf("expected 0 locks, got %d", len(locks))
	}

	// Add some locks
	repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "lock-1", 5*time.Minute, "owner-1")
	repo.TryAcquire(ctx, repository.LockTypeFileDeletion, "lock-2", 5*time.Minute, "owner-2")
	repo.TryAcquire(ctx, repository.LockTypeBackup, "lock-3", 5*time.Minute, "owner-3")

	// Get all locks
	locks, err = repo.GetAllLocks(ctx)
	if err != nil {
		t.Fatalf("GetAllLocks failed: %v", err)
	}
	if len(locks) != 3 {
		t.Errorf("expected 3 locks, got %d", len(locks))
	}
}

func TestLockRepository_ValidationErrors(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Invalid lock type
	_, _, err := repo.TryAcquire(ctx, "invalid_type", "key", 5*time.Minute, "owner")
	if err == nil {
		t.Error("expected error for invalid lock type")
	}

	// Empty lock key
	_, _, err = repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "", 5*time.Minute, "owner")
	if err != repository.ErrInvalidLockKey {
		t.Errorf("expected ErrInvalidLockKey, got: %v", err)
	}

	// Empty owner ID
	_, _, err = repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "key", 5*time.Minute, "")
	if err == nil {
		t.Error("expected error for empty owner ID")
	}

	// Invalid TTL
	_, _, err = repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "key", 0, "owner")
	if err == nil {
		t.Error("expected error for zero TTL")
	}

	// Lock key too long
	longKey := string(make([]byte, 300))
	_, _, err = repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, longKey, 5*time.Minute, "owner")
	if err != repository.ErrInvalidLockKey {
		t.Errorf("expected ErrInvalidLockKey for long key, got: %v", err)
	}
}

func TestLockRepository_Acquire_Timeout(t *testing.T) {
	db := setupLockTestDB(t)
	defer db.Close()

	repo := NewLockRepository(db)
	ctx := context.Background()

	// Acquire lock with owner-1
	_, _, err := repo.TryAcquire(ctx, repository.LockTypeChunkAssembly, "contested-lock", 5*time.Minute, "owner-1")
	if err != nil {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// Try to acquire with owner-2 with short timeout
	_, err = repo.Acquire(ctx, repository.LockTypeChunkAssembly, "contested-lock", 5*time.Minute, 500*time.Millisecond, "owner-2")
	if err != repository.ErrLockTimeout {
		t.Errorf("expected ErrLockTimeout, got: %v", err)
	}
}
