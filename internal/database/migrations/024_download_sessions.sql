-- Migration 024: Download sessions (T1/T5 fix; see ADR-014, amends ADR-012)
--
-- Replaces the download_reservations table (migration 023) with a richer
-- download_sessions table that survives across separate HTTP requests. This
-- closes two holes left by the reservation pattern:
--
--   T1: Range-splitting a download (bytes=0-(N-2), then (N-1)-) was never
--       counted toward max_downloads, because each Range request ran its own
--       independent Reserve/Commit/Cancel cycle and a partial-coverage
--       request never committed. A client — including the web UI's own
--       pause/resume feature — could download a max_downloads=1 file an
--       unlimited number of times by always stopping one byte short.
--   T5: the reservation TTL (30m) was shorter than the maximum transfer
--       deadline (up to 6h — see extendTransferDeadline in
--       internal/handlers/helpers.go), so the reaper could free a
--       reservation that was still genuinely in flight, letting a second
--       reader take the same slot while the first stream was still being
--       written (double delivery).
--
-- download_sessions rows carry a bearer token (stored only as its SHA-256
-- hash — see internal/repository/sqlite/file_repository.go) that the client
-- echoes back across Range-resume requests via the X-Download-Session
-- response/request header. See internal/handlers/session_writer.go for the
-- commit-threshold logic and internal/utils/reservation_reaper.go for the
-- lease/idle/max-age reaping that replaces the old single-TTL reaper.
--
-- Rows in download_reservations only ever represented live, in-flight state
-- from a running process — anything still there at migration time is from a
-- dead process (a crash, or simply the previous release). Clear it and reset
-- the denormalised in_flight_reservations counter before dropping the table
-- so no file is left with a stuck non-zero counter.

DELETE FROM download_reservations;
UPDATE files SET in_flight_reservations = 0;

DROP TABLE IF EXISTS download_reservations;

CREATE TABLE IF NOT EXISTS download_sessions (
    token_hash           TEXT     PRIMARY KEY,
    file_id              INTEGER  NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    committed_at         DATETIME,
    completed_at         DATETIME,
    bytes_served         INTEGER  NOT NULL DEFAULT 0,
    -- Probe-threshold bytes atomically granted to this session at Reserve
    -- time (charged against files.uncounted_bytes in the same transaction —
    -- see ReserveDownload). Refunded as (probe_bytes_granted - bytes_served)
    -- on Cancel/abandon, or in full on Commit (the download is no longer an
    -- "uncounted probe" once it's credited). Storing it on the row, rather
    -- than trusting a caller-supplied value, keeps the refund correct no
    -- matter which code path (Cancel, Commit, the reaper) eventually closes
    -- the session.
    probe_bytes_granted  INTEGER  NOT NULL DEFAULT 0,
    -- Cumulative bytes reserved (not necessarily delivered) by trusted-token
    -- replay requests against an already-resolved session — see
    -- ReserveSessionBytes. Bounded by ~2x the file size so a committed
    -- session's token cannot be replayed to redeliver the whole file an
    -- unbounded number of times (bug-hunter finding: LookupDownloadSession
    -- alone only checked idle/max-age TTLs, never completion or bytes
    -- served, so a committed token could be curled forever within its TTL).
    -- Each request reserves its full range up front and releases the part it
    -- didn't send at the end, so the ceiling tracks bytes actually delivered.
    bytes_reserved       INTEGER  NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_dl_sessions_file_id
    ON download_sessions(file_id);

-- Used by the reaper to find committed-but-idle and stale-uncommitted rows
-- without a full table scan.
CREATE INDEX IF NOT EXISTS idx_dl_sessions_committed_last_seen
    ON download_sessions(committed_at, last_seen_at);

-- Cumulative bytes served to tokenless "probe" requests that were cancelled
-- before crossing the per-request commit threshold P (see
-- internal/handlers/session_writer.go). Once a file's uncounted_bytes reaches
-- budget B = 4*P, every subsequent tokenless byte on that file counts
-- immediately (P collapses to 0) — this closes the salami-slicing variant of
-- T1 where a client deliberately stays just under P on every request.
ALTER TABLE files ADD COLUMN uncounted_bytes INTEGER NOT NULL DEFAULT 0;
