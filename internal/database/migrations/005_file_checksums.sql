-- Migration 005: Add SHA256 checksums to files table
--
-- Adds sha256_hash column to track file integrity:
-- - Computed on upload (before encryption for user verification)
-- - Enables corruption detection
-- - Supports backup verification
-- - Allows client-side verification
--
-- Date: 2025-01-16
-- Version: v2.1.0

-- Add sha256_hash column to files table
ALTER TABLE files ADD COLUMN sha256_hash TEXT;

-- Create index for potential future lookups (deduplication, etc.)
CREATE INDEX IF NOT EXISTS idx_sha256_hash ON files(sha256_hash);
