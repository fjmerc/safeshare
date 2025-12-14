-- Migration 014: Backup scheduler tables
-- Adds support for scheduled automatic backups

-- Table: backup_schedules - Stores scheduled backup configurations
-- Each row represents a backup schedule that can run automatically
CREATE TABLE IF NOT EXISTS backup_schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,              -- Schedule name (e.g., "daily-full", "hourly-config")
    enabled INTEGER NOT NULL DEFAULT 1,     -- Is schedule active (0=disabled, 1=enabled)
    schedule TEXT NOT NULL,                 -- Cron expression (e.g., "0 2 * * *")
    mode TEXT NOT NULL DEFAULT 'full',      -- Backup mode: full, database, config
    retention_days INTEGER NOT NULL DEFAULT 30, -- Days to keep backups (0=unlimited)
    last_run_at TEXT,                       -- ISO8601 timestamp of last execution
    next_run_at TEXT,                       -- ISO8601 timestamp of next scheduled execution
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Table: backup_runs - Stores history of backup executions
-- Tracks both scheduled and manual backup runs
CREATE TABLE IF NOT EXISTS backup_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id INTEGER,                    -- FK to backup_schedules (NULL for manual backups)
    trigger_type TEXT NOT NULL DEFAULT 'manual', -- How backup was triggered: manual, scheduled, api
    status TEXT NOT NULL DEFAULT 'pending', -- Job status: pending, running, completed, failed
    mode TEXT NOT NULL,                     -- Backup mode used: full, database, config
    output_path TEXT,                       -- Path to backup directory
    size_bytes INTEGER DEFAULT 0,           -- Total backup size in bytes
    files_backed_up INTEGER DEFAULT 0,      -- Number of files backed up
    error_message TEXT,                     -- Error message if failed
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    completed_at TEXT,                      -- ISO8601 timestamp when completed
    duration_ms INTEGER DEFAULT 0,          -- Duration in milliseconds
    FOREIGN KEY (schedule_id) REFERENCES backup_schedules(id) ON DELETE SET NULL
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_backup_schedules_enabled ON backup_schedules(enabled);
CREATE INDEX IF NOT EXISTS idx_backup_schedules_next_run ON backup_schedules(next_run_at) WHERE enabled = 1;
CREATE INDEX IF NOT EXISTS idx_backup_runs_schedule ON backup_runs(schedule_id);
CREATE INDEX IF NOT EXISTS idx_backup_runs_status ON backup_runs(status);
CREATE INDEX IF NOT EXISTS idx_backup_runs_started_at ON backup_runs(started_at);
CREATE INDEX IF NOT EXISTS idx_backup_runs_completed_at ON backup_runs(completed_at);

-- Insert default schedule (disabled by default)
-- Users can enable via admin UI or environment variable
INSERT OR IGNORE INTO backup_schedules (name, enabled, schedule, mode, retention_days)
VALUES ('default', 0, '0 2 * * *', 'full', 30);
