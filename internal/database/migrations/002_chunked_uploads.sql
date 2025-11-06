-- Migration 002: Chunked Uploads Support
--
-- This migration adds support for chunked/resumable uploads for large files.
-- It creates the partial_uploads table to track upload sessions and their progress.
--
-- Date: 2025-01-06
-- Version: v2.0.0

CREATE TABLE IF NOT EXISTS partial_uploads (
    upload_id TEXT PRIMARY KEY,              -- UUID for upload session
    user_id INTEGER,                          -- FK to users table (nullable for anonymous uploads)
    filename TEXT NOT NULL,                   -- Original filename
    total_size INTEGER NOT NULL,              -- Expected total file size in bytes
    chunk_size INTEGER NOT NULL,              -- Size of each chunk in bytes (except last)
    total_chunks INTEGER NOT NULL,            -- Expected number of chunks
    chunks_received INTEGER DEFAULT 0,        -- Counter of received chunks
    received_bytes INTEGER DEFAULT 0,         -- Total bytes received (for quota tracking)
    expires_in_hours INTEGER NOT NULL,        -- User-requested expiration (hours)
    max_downloads INTEGER NOT NULL,           -- User-requested download limit
    password_hash TEXT,                       -- Optional password protection
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed INTEGER DEFAULT 0,              -- Boolean: whether all chunks received (0/1)
    claim_code TEXT,                          -- Final claim code (NULL until completed)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_partial_uploads_last_activity ON partial_uploads(last_activity);
CREATE INDEX IF NOT EXISTS idx_partial_uploads_completed ON partial_uploads(completed);
CREATE INDEX IF NOT EXISTS idx_partial_uploads_user_id ON partial_uploads(user_id);
CREATE INDEX IF NOT EXISTS idx_partial_uploads_upload_id ON partial_uploads(upload_id);
