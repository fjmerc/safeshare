-- 026_assembly_lease.sql
-- ADR-016: reliable chunked-upload assembly (lease-based state machine).
--
-- Replaces the old unconditional "processing older than 1h -> reset and
-- reassemble" recovery with a fenced-lease compare-and-swap: every
-- processing->* transition is guarded by status AND a per-attempt owner
-- token, so a stale worker that wakes up after a takeover can never
-- overwrite the winner's result (T20/T21 in the ADR).
--
-- processing_owner / lease_expires_at: the fencing token + TTL a worker
-- holds while assembling. NULL processing_owner means "never leased" (e.g.
-- an old row from before this migration) and is treated as expired.
--
-- assembly_attempts: incremented every time a row transitions into
-- "processing" (Lock/TakeOver), capped at ASSEMBLY_MAX_ATTEMPTS. Backfilled
-- to 1 for any row that has ever reached processing/failed/completed, since
-- it necessarily consumed at least one attempt under the old code.
--
-- error_retryable: persisted at failure time so /complete and /status don't
-- have to re-derive "is this worth retrying" from error_code. Existing
-- failed rows are backfilled retryable for the two failure reasons that were
-- already transient under ADR-015 (SCAN_UNAVAILABLE, and the catch-all
-- ASSEMBLY_FAILED, which covers IO/DB/encryption/chunk errors) *and* for a
-- NULL error_code, since every pre-ADR-016 failure path except the
-- MALWARE_DETECTED one left error_code unset (see the old SetAssemblyFailed
-- call sites) — treating NULL as terminal would have wrongly stuck a large
-- share of legacy failed rows. MALWARE_DETECTED (and any other,
-- unrecognized error_code) stays terminal, error_retryable's default.
--
-- Two ASSEMBLY_FAILED/NULL-coded messages are excluded from that backfill
-- (DB-review finding L3): pre-ADR-016 code recorded a scanned/assembled
-- content (TOCTOU) mismatch as error_code='ASSEMBLY_FAILED' with the fixed
-- message 'Upload could not be verified and was rejected', and an assembled
-- file size mismatch as error_code=NULL with message LIKE 'Assembled file
-- size mismatch%'. Both are the same class of failure ADR-016 itself now
-- gives its own terminal INTEGRITY_ERROR code — retrying either just re-runs
-- the same already-resolved race/corruption, so legacy rows matching these
-- messages are backfilled terminal (error_retryable stays 0), not retryable.
--
-- uploader_ip: captured at init time so a recovered/taken-over assembly
-- keeps the real uploader IP in the eventual file record instead of a
-- synthetic placeholder (T21 bug-hunter finding: "recovery-worker" was
-- landing in files.uploader_ip).
ALTER TABLE partial_uploads ADD COLUMN processing_owner TEXT DEFAULT NULL;
ALTER TABLE partial_uploads ADD COLUMN lease_expires_at TEXT DEFAULT NULL;
ALTER TABLE partial_uploads ADD COLUMN assembly_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE partial_uploads ADD COLUMN error_retryable INTEGER NOT NULL DEFAULT 0;
ALTER TABLE partial_uploads ADD COLUMN uploader_ip TEXT DEFAULT NULL;

UPDATE partial_uploads
SET assembly_attempts = 1
WHERE status IN ('processing', 'failed', 'completed');

UPDATE partial_uploads
SET error_retryable = 1
WHERE status = 'failed'
  AND (error_code IS NULL OR error_code IN ('SCAN_UNAVAILABLE', 'ASSEMBLY_FAILED'))
  AND (error_message IS NULL OR error_message != 'Upload could not be verified and was rejected')
  AND (error_message IS NULL OR error_message NOT LIKE 'Assembled file size mismatch%');

-- Existing 'processing' rows intentionally keep lease_expires_at = NULL:
-- NULL is treated as an expired lease everywhere (TakeOver/ExhaustExpired),
-- so they become takeover candidates for the recovery worker on first boot
-- after this migration, exactly as a crashed worker's row would be.

-- Ties a file row back to the chunked-upload session it was assembled
-- from. The unique partial index enforces the publish-side half of the
-- fencing invariant: at most one file row can ever exist per upload_id,
-- so even if two owner-guarded UPDATEs somehow both matched (should be
-- impossible under the CAS), the second file insert fails closed.
ALTER TABLE files ADD COLUMN partial_upload_id TEXT DEFAULT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_files_partial_upload_id
    ON files(partial_upload_id)
    WHERE partial_upload_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_partial_uploads_status_lease
    ON partial_uploads(status, lease_expires_at);
