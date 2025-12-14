-- Migration 013: Distributed Locks
-- This table supports distributed locking for multi-node deployments.
-- For SQLite (single-node), this provides coordination within the instance.
-- For PostgreSQL, this is used alongside pg_advisory_lock for true distributed locking.

CREATE TABLE IF NOT EXISTS distributed_locks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lock_type TEXT NOT NULL,           -- Type of lock (chunk_assembly, file_deletion, etc.)
    lock_key TEXT NOT NULL,            -- Unique key for the locked resource
    owner_id TEXT NOT NULL,            -- Identifier of the lock holder (hostname:pid)
    acquired_at TEXT NOT NULL,         -- When the lock was acquired
    expires_at TEXT NOT NULL,          -- When the lock expires (safety timeout)
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT,
    UNIQUE(lock_type, lock_key)        -- Only one lock per type+key
);

-- Index for efficient expiration cleanup
CREATE INDEX IF NOT EXISTS idx_distributed_locks_expires_at ON distributed_locks(expires_at);

-- Index for querying locks by type
CREATE INDEX IF NOT EXISTS idx_distributed_locks_type ON distributed_locks(lock_type);

-- Index for querying locks by owner (useful for debugging)
CREATE INDEX IF NOT EXISTS idx_distributed_locks_owner ON distributed_locks(owner_id);
