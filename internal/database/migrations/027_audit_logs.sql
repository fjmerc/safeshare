-- 027_audit_logs.sql
-- ADR-018: tamper-evident audit log.
--
-- Each entry is chained to the previous one (prev_hash) and signed with an
-- HMAC over all of its fields (entry_hash), keyed by a secret that is not
-- stored in the database. Ids are assigned by the application inside the
-- append transaction, so they are contiguous: a deleted entry shows up as
-- a gap, an edited one as a bad hash. Every column is stored exactly as it
-- is hashed (fixed-width UTC timestamp text, '' rather than NULL).
CREATE TABLE IF NOT EXISTS audit_logs (
    id            INTEGER PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    action        TEXT NOT NULL,
    outcome       TEXT NOT NULL,
    user_id       TEXT NOT NULL DEFAULT '',
    username      TEXT NOT NULL DEFAULT '',
    ip_address    TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id   TEXT NOT NULL DEFAULT '',
    details       TEXT NOT NULL DEFAULT '',
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL,
    key_id        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type, id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_username ON audit_logs(username, id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address, id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id, id);

-- Singleton: where the verifiable chain starts once retention has pruned
-- old entries (the last pruned entry's id and hash), and the retention
-- period itself (0 = keep forever).
CREATE TABLE IF NOT EXISTS audit_log_state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    anchor_id      INTEGER NOT NULL DEFAULT 0,
    anchor_hash    TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    retention_days INTEGER NOT NULL DEFAULT 365
);

INSERT OR IGNORE INTO audit_log_state (id) VALUES (1);
