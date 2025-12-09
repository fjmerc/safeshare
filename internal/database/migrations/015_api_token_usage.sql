-- Migration: 015_api_token_usage.sql
-- Description: Create api_token_usage table for tracking API token usage audit logs
-- Date: 2025-12-09

-- Create api_token_usage table
CREATE TABLE IF NOT EXISTS api_token_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    endpoint TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    response_status INTEGER NOT NULL,
    FOREIGN KEY (token_id) REFERENCES api_tokens(id) ON DELETE CASCADE
);

-- Create composite index on token_id and timestamp for efficient queries
-- Most queries will filter by token_id and order/filter by timestamp
CREATE INDEX IF NOT EXISTS idx_api_token_usage_token_timestamp 
    ON api_token_usage(token_id, timestamp DESC);

-- Create index on timestamp alone for cleanup operations
CREATE INDEX IF NOT EXISTS idx_api_token_usage_timestamp 
    ON api_token_usage(timestamp);
