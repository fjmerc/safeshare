-- Add format column to webhook_configs table
ALTER TABLE webhook_configs ADD COLUMN format TEXT NOT NULL DEFAULT 'safeshare';
