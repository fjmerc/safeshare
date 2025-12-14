-- Migration: 016_api_token_usage_stats_indexes.sql
-- Description: Add indexes for GetUsageStats queries (unique IPs and top endpoints)
-- Date: 2025-12-09

-- Index for unique IP count queries
-- Supports: SELECT COUNT(DISTINCT ip_address) FROM api_token_usage WHERE token_id = ?
CREATE INDEX IF NOT EXISTS idx_api_token_usage_token_ip 
    ON api_token_usage(token_id, ip_address);

-- Index for top endpoints queries
-- Supports: SELECT endpoint, COUNT(*) FROM api_token_usage WHERE token_id = ? GROUP BY endpoint
CREATE INDEX IF NOT EXISTS idx_api_token_usage_token_endpoint 
    ON api_token_usage(token_id, endpoint);
