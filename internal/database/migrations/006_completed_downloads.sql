-- Migration 006: Add completed downloads tracking
--
-- Adds completed_downloads column to distinguish full file downloads from HTTP requests:
-- - Tracks only successfully completed full file downloads (HTTP 200 OK)
-- - Does NOT count partial/range downloads (HTTP 206 Partial Content)
-- - Does NOT count failed or interrupted downloads
-- - Provides accurate user-facing download statistics
--
-- The existing download_count field is retained for:
-- - Rate limiting and abuse prevention
-- - Enforcing max_downloads quotas
-- - Tracking all HTTP requests (including ranges)
--
-- Date: 2025-01-21
-- Version: v2.8.0

-- Add completed_downloads column to files table
ALTER TABLE files ADD COLUMN completed_downloads INTEGER DEFAULT 0;
