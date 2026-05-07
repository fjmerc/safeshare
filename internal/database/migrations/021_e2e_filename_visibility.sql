-- Migration 021: Track client-side (E2E) encryption flag
--
-- Adds client_encrypted boolean to files and partial_uploads to mark records
-- whose contents were encrypted in the browser before upload.
--
-- This decouples E2E detection from the previous "filename === 'encrypted.bin'"
-- heuristic so users can opt to keep the original filename visible to the server
-- while still encrypting the content client-side.
--
-- Backward compatibility: existing rows default to 0 (false). The frontend keeps
-- a fallback that treats original_filename === 'encrypted.bin' as E2E so files
-- uploaded before this migration continue to prompt for the decryption key.

ALTER TABLE files ADD COLUMN client_encrypted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE partial_uploads ADD COLUMN client_encrypted INTEGER NOT NULL DEFAULT 0;
