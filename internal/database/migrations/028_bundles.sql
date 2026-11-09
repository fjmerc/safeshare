-- 028_bundles.sql
-- Multi-file bundles: one code and one link for a set of files.
--
-- A bundle owns its member files (files.bundle_id). It is created as a
-- draft, members are uploaded into it through the normal upload endpoints,
-- and it becomes reachable by bundle_code only once published. The
-- bundle's settings (expiry, download limit, password, owner) are mirrored
-- onto every member row so the existing enforcement code applies unchanged.
--
-- files.bundle_id has no ON DELETE action on purpose: deleting a bundle
-- that still has members fails, so member rows (and their stored files)
-- are always removed explicitly first and never left pointing nowhere.
CREATE TABLE IF NOT EXISTS bundles (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_code        TEXT UNIQUE NOT NULL,
    status             TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
    file_count         INTEGER NOT NULL CHECK (file_count > 0),
    upload_token_hash  TEXT NOT NULL,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    published_at       TEXT,
    expires_at         TEXT NOT NULL,
    max_downloads      INTEGER,
    password_hash      TEXT,
    user_id            INTEGER REFERENCES users(id) ON DELETE SET NULL,
    client_encrypted   INTEGER NOT NULL DEFAULT 0,
    encrypted_manifest BLOB,
    uploader_ip        TEXT
);

CREATE INDEX IF NOT EXISTS idx_bundles_expires_at ON bundles(expires_at);
CREATE INDEX IF NOT EXISTS idx_bundles_user_id ON bundles(user_id);
CREATE INDEX IF NOT EXISTS idx_bundles_status ON bundles(status);

ALTER TABLE files ADD COLUMN bundle_id INTEGER REFERENCES bundles(id);
ALTER TABLE files ADD COLUMN bundle_position INTEGER;

CREATE INDEX IF NOT EXISTS idx_files_bundle_id ON files(bundle_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_files_bundle_position
    ON files(bundle_id, bundle_position)
    WHERE bundle_id IS NOT NULL;

ALTER TABLE partial_uploads ADD COLUMN bundle_id INTEGER;
ALTER TABLE partial_uploads ADD COLUMN bundle_position INTEGER;

CREATE INDEX IF NOT EXISTS idx_partial_uploads_bundle ON partial_uploads(bundle_id, bundle_position);
