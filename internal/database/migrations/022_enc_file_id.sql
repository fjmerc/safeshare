-- Migration 022: Add per-file random identifier for SFSE2 streaming encryption
--
-- Adds enc_file_id to files: a 16-byte random value generated on first
-- encryption. The value is bound into the AAD of every chunk in the SFSE2
-- streaming encryption format, defeating cross-file splice attacks against
-- the encrypted-at-rest blob (see ADR-011).
--
-- Decoupled from files.id (BIGINT autoincrement) so the identifier survives
-- DB rebuild, backup/restore, and cross-instance file import.
--
-- Backward compatibility:
--   - NULL (default) means the file is legacy SFSE1 with no AAD binding.
--   - Reader path: dispatcher peeks the on-disk version byte; SFSE1 (NULL
--     enc_file_id) routes to the legacy reader, SFSE2 to the AAD-checked
--     reader.

ALTER TABLE files ADD COLUMN enc_file_id BLOB;
