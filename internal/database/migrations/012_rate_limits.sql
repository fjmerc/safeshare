-- Migration 012: Rate limits table for database-backed rate limiting
-- Enables multi-node deployments where rate limits are shared across instances

CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    limit_type TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    window_end TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address, limit_type)
);

-- Index for efficient lookups by IP and type
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_type ON rate_limits(ip_address, limit_type);

-- Index for cleanup worker to find expired entries efficiently
CREATE INDEX IF NOT EXISTS idx_rate_limits_window_end ON rate_limits(window_end);
