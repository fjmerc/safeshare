-- Migration 023: Download reservation pattern (SH-2.3 / ADR-012)
--
-- Adds the two-phase commit infrastructure for the download counter:
--   1. files.in_flight_reservations  - denormalised counter of live reservations
--   2. download_reservations table   - one row per live reservation handle
--
-- The reservation pattern fixes a denial-of-access bug where a partial-Range
-- probe (or browser pre-fetch, link preview crawler, network blip) consumed
-- the only download of a max_downloads=1 file before the legitimate recipient
-- received any bytes. With reservations, download_count is incremented only
-- on successful full-file delivery; partial probes increment in_flight while
-- streaming but decrement it (via Cancel) on completion without touching
-- download_count.
--
-- The reaper (internal/utils/reservation_reaper.go) deletes stale rows and
-- decrements in_flight_reservations on a fixed 1-minute tick. TTL is operator-
-- configurable via DOWNLOAD_RESERVATION_TTL (default 30 minutes).

ALTER TABLE files ADD COLUMN in_flight_reservations INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS download_reservations (
    token      TEXT     PRIMARY KEY,
    file_id    INTEGER  NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dl_reservations_created_at
    ON download_reservations(created_at);

CREATE INDEX IF NOT EXISTS idx_dl_reservations_file_id
    ON download_reservations(file_id);
