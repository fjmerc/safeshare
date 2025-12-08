// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"fmt"
	"log/slog"
)

// Migration represents a database migration.
type Migration struct {
	Version     int
	Name        string
	Description string
	SQL         string
}

// migrations contains all PostgreSQL schema migrations in order.
var migrations = []Migration{
	{
		Version:     1,
		Name:        "001_initial",
		Description: "Initial PostgreSQL schema with all core tables",
		SQL: `
-- ============================================================================
-- MIGRATIONS TABLE (for tracking applied migrations)
-- ============================================================================
CREATE TABLE IF NOT EXISTS migrations (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_migrations_name ON migrations(name);

-- ============================================================================
-- USERS TABLE (created first - files table has FK reference)
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    is_approved BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    require_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ============================================================================
-- FILES TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS files (
    id BIGSERIAL PRIMARY KEY,
    claim_code TEXT UNIQUE NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    max_downloads INTEGER,
    download_count INTEGER DEFAULT 0,
    completed_downloads INTEGER DEFAULT 0,
    uploader_ip TEXT,
    password_hash TEXT,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    sha256_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_files_claim_code ON files(claim_code);
CREATE INDEX IF NOT EXISTS idx_files_expires_at ON files(expires_at);
CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at DESC);

-- ============================================================================
-- USER SESSIONS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT NOT NULL,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);

-- ============================================================================
-- ADMIN TABLES
-- ============================================================================
CREATE TABLE IF NOT EXISTS admin_credentials (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id BIGSERIAL PRIMARY KEY,
    session_token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT NOT NULL,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);

-- ============================================================================
-- BLOCKED IPS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS blocked_ips (
    id BIGSERIAL PRIMARY KEY,
    ip_address TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    blocked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    blocked_by TEXT DEFAULT 'admin'
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip_address ON blocked_ips(ip_address);

-- ============================================================================
-- SETTINGS TABLE (with all feature flags)
-- ============================================================================
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    quota_limit_gb BIGINT DEFAULT 0,
    max_file_size_bytes BIGINT DEFAULT 104857600,
    default_expiration_hours INTEGER DEFAULT 24,
    max_expiration_hours INTEGER DEFAULT 168,
    rate_limit_upload INTEGER DEFAULT 10,
    rate_limit_download INTEGER DEFAULT 100,
    blocked_extensions TEXT DEFAULT '.exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar,.com,.app,.deb,.rpm',
    feature_postgresql BOOLEAN NOT NULL DEFAULT FALSE,
    feature_s3_storage BOOLEAN NOT NULL DEFAULT FALSE,
    feature_sso BOOLEAN NOT NULL DEFAULT FALSE,
    feature_mfa BOOLEAN NOT NULL DEFAULT FALSE,
    feature_webhooks BOOLEAN NOT NULL DEFAULT FALSE,
    feature_api_tokens BOOLEAN NOT NULL DEFAULT FALSE,
    feature_malware_scan BOOLEAN NOT NULL DEFAULT FALSE,
    feature_backups BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- PARTIAL UPLOADS TABLE (chunked uploads)
-- ============================================================================
CREATE TABLE IF NOT EXISTS partial_uploads (
    upload_id TEXT PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    total_size BIGINT NOT NULL,
    chunk_size INTEGER NOT NULL,
    total_chunks INTEGER NOT NULL,
    chunks_received INTEGER DEFAULT 0,
    received_bytes BIGINT DEFAULT 0,
    expires_in_hours INTEGER NOT NULL,
    max_downloads INTEGER NOT NULL,
    password_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed BOOLEAN DEFAULT FALSE,
    claim_code TEXT,
    status TEXT NOT NULL DEFAULT 'uploading',
    error_message TEXT,
    assembly_started_at TIMESTAMPTZ,
    assembly_completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_partial_uploads_last_activity ON partial_uploads(last_activity);
CREATE INDEX IF NOT EXISTS idx_partial_uploads_completed ON partial_uploads(completed);
CREATE INDEX IF NOT EXISTS idx_partial_uploads_user_id ON partial_uploads(user_id);
CREATE INDEX IF NOT EXISTS idx_partial_uploads_status ON partial_uploads(status);

-- ============================================================================
-- WEBHOOK TABLES
-- ============================================================================
CREATE TABLE IF NOT EXISTS webhook_configs (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    events TEXT NOT NULL,
    max_retries INTEGER NOT NULL DEFAULT 5,
    timeout_seconds INTEGER NOT NULL DEFAULT 30,
    format TEXT NOT NULL DEFAULT 'safeshare',
    service_token TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhook_configs_enabled ON webhook_configs(enabled);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id BIGSERIAL PRIMARY KEY,
    webhook_config_id BIGINT NOT NULL REFERENCES webhook_configs(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    response_code INTEGER,
    response_body TEXT,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_config_id ON webhook_deliveries(webhook_config_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created_at ON webhook_deliveries(created_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_next_retry ON webhook_deliveries(next_retry_at);

-- ============================================================================
-- API TOKENS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    scopes TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_ip TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_ip TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_is_active ON api_tokens(is_active);
CREATE INDEX IF NOT EXISTS idx_api_tokens_expires_at ON api_tokens(expires_at);
`,
	},
	{
		Version:     2,
		Name:        "002_rate_limits",
		Description: "Rate limits table for database-backed rate limiting (HA support)",
		SQL: `
-- ============================================================================
-- RATE LIMITS TABLE (for multi-node rate limiting)
-- ============================================================================
CREATE TABLE IF NOT EXISTS rate_limits (
    id BIGSERIAL PRIMARY KEY,
    ip_address TEXT NOT NULL,
    limit_type TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 1,
    window_end TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address, limit_type)
);

-- Index for efficient lookups by IP and type
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_type ON rate_limits(ip_address, limit_type);

-- Index for cleanup worker to find expired entries efficiently
CREATE INDEX IF NOT EXISTS idx_rate_limits_window_end ON rate_limits(window_end);
`,
	},
	{
		Version:     3,
		Name:        "003_distributed_locks",
		Description: "Distributed locks table for multi-node coordination (HA support)",
		SQL: `
-- ============================================================================
-- DISTRIBUTED LOCKS TABLE (for multi-node locking)
-- ============================================================================
-- This table is used alongside PostgreSQL advisory locks for:
-- 1. Visibility into held locks (debugging/monitoring)
-- 2. TTL-based expiration (safety net)
-- 3. Lock metadata storage
--
-- The actual locking is done via pg_advisory_lock for performance.

CREATE TABLE IF NOT EXISTS distributed_locks (
    id BIGSERIAL PRIMARY KEY,
    lock_type TEXT NOT NULL,           -- Type of lock (chunk_assembly, file_deletion, etc.)
    lock_key TEXT NOT NULL,            -- Unique key for the locked resource
    owner_id TEXT NOT NULL,            -- Identifier of the lock holder (hostname:pid)
    acquired_at TIMESTAMPTZ NOT NULL,  -- When the lock was acquired
    expires_at TIMESTAMPTZ NOT NULL,   -- When the lock expires (safety timeout)
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    UNIQUE(lock_type, lock_key)        -- Only one lock per type+key
);

-- Index for efficient expiration cleanup
CREATE INDEX IF NOT EXISTS idx_distributed_locks_expires_at ON distributed_locks(expires_at);

-- Index for querying locks by type
CREATE INDEX IF NOT EXISTS idx_distributed_locks_type ON distributed_locks(lock_type);

-- Index for querying locks by owner (useful for debugging)
CREATE INDEX IF NOT EXISTS idx_distributed_locks_owner ON distributed_locks(owner_id);
`,
	},
}

// RunMigrations applies all pending database migrations to PostgreSQL.
func RunMigrations(ctx context.Context, pool *Pool) error {
	slog.Info("running PostgreSQL database migrations")

	// Ensure migrations table exists
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS migrations (
			id SERIAL PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get list of applied migrations
	appliedMap := make(map[string]bool)
	rows, err := pool.Query(ctx, "SELECT name FROM migrations")
	if err != nil {
		return fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("failed to scan migration name: %w", err)
		}
		appliedMap[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating migrations: %w", err)
	}

	// Apply pending migrations
	pendingCount := 0
	for _, m := range migrations {
		if appliedMap[m.Name] {
			slog.Debug("migration already applied", "migration", m.Name)
			continue
		}

		slog.Info("applying migration", "migration", m.Name, "description", m.Description)

		// Execute migration in a transaction
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %s: %w", m.Name, err)
		}

		// Execute migration SQL
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("failed to execute migration %s: %w", m.Name, err)
		}

		// Record migration as applied
		if _, err := tx.Exec(ctx, "INSERT INTO migrations (name) VALUES ($1)", m.Name); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("failed to record migration %s: %w", m.Name, err)
		}

		// Commit transaction
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", m.Name, err)
		}

		slog.Info("migration applied successfully", "migration", m.Name)
		pendingCount++
	}

	if pendingCount == 0 {
		slog.Info("no pending PostgreSQL migrations")
	} else {
		slog.Info("PostgreSQL migrations complete", "applied", pendingCount)
	}

	return nil
}

// GetMigrationStatus returns the status of all migrations.
func GetMigrationStatus(ctx context.Context, pool *Pool) ([]MigrationStatus, error) {
	// Get applied migrations
	appliedMap := make(map[string]bool)
	rows, err := pool.Query(ctx, "SELECT name FROM migrations ORDER BY id")
	if err != nil {
		// Table might not exist yet
		return nil, nil
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan migration name: %w", err)
		}
		appliedMap[name] = true
	}

	var status []MigrationStatus
	for _, m := range migrations {
		status = append(status, MigrationStatus{
			Version:     m.Version,
			Name:        m.Name,
			Description: m.Description,
			Applied:     appliedMap[m.Name],
		})
	}

	return status, nil
}

// MigrationStatus represents the status of a migration.
type MigrationStatus struct {
	Version     int
	Name        string
	Description string
	Applied     bool
}
