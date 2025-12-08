-- Feature flags for enterprise features
-- All flags default to 0 (false/disabled) for safety

-- Add feature flag columns to settings table
-- Using INTEGER type where 0 = false, 1 = true (SQLite doesn't have native boolean)

ALTER TABLE settings ADD COLUMN feature_postgresql INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN feature_s3_storage INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN feature_sso INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN feature_mfa INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN feature_webhooks INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN feature_api_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN feature_malware_scan INTEGER NOT NULL DEFAULT 0;
ALTER TABLE settings ADD COLUMN feature_backups INTEGER NOT NULL DEFAULT 0;
