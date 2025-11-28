-- Add service_token column to webhook_configs table
-- This column stores authentication tokens for webhook services (Gotify, ntfy, etc.)
-- Nullable because not all webhook formats require service tokens (Discord, SafeShare use other auth methods)
ALTER TABLE webhook_configs ADD COLUMN service_token TEXT;
