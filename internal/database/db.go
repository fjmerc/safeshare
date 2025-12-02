package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    claim_code TEXT UNIQUE NOT NULL,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    max_downloads INTEGER,
    download_count INTEGER DEFAULT 0,
    uploader_ip TEXT,
    password_hash TEXT,
    user_id INTEGER,
    UNIQUE(claim_code),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_claim_code ON files(claim_code);
CREATE INDEX IF NOT EXISTS idx_expires_at ON files(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_id ON files(user_id);
`

// Migration to add password_hash column to existing databases
const migration = `
ALTER TABLE files ADD COLUMN password_hash TEXT;
`

// User schema for authentication
const userSchema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    is_approved INTEGER NOT NULL DEFAULT 1,
    is_active INTEGER NOT NULL DEFAULT 1,
    require_password_change INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    UNIQUE(username),
    UNIQUE(email)
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    UNIQUE(session_token),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_user_session_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_session_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_id ON user_sessions(user_id);
`

// Migration to add user_id to existing files table
const userMigration = `
ALTER TABLE files ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
`

// Admin-related schema
const adminSchema = `
CREATE TABLE IF NOT EXISTS admin_credentials (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    reason TEXT NOT NULL,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    blocked_by TEXT DEFAULT 'admin',
    UNIQUE(ip_address)
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    UNIQUE(session_token)
);

CREATE INDEX IF NOT EXISTS idx_session_token ON admin_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_session_expires ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip_address);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    quota_limit_gb INTEGER DEFAULT 0,
    max_file_size_bytes INTEGER DEFAULT 104857600,
    default_expiration_hours INTEGER DEFAULT 24,
    max_expiration_hours INTEGER DEFAULT 168,
    rate_limit_upload INTEGER DEFAULT 10,
    rate_limit_download INTEGER DEFAULT 100,
    blocked_extensions TEXT DEFAULT '.exe,.bat,.cmd,.sh,.ps1,.dll,.so,.msi,.scr,.vbs,.jar,.com,.app,.deb,.rpm',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

// connectionHookOnce ensures we only register the connection hook once
var connectionHookOnce sync.Once

// registerConnectionHook sets up a hook that applies SQLite pragmas to ALL new connections.
// This is critical because database/sql connection pooling can create new connections
// that don't inherit pragmas set on the initial connection.
func registerConnectionHook() {
	connectionHookOnce.Do(func() {
		sqlite.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, dsn string) error {
			// Apply critical pragmas to each new connection
			// These MUST be applied per-connection as they are connection-level settings
			pragmas := []string{
				"PRAGMA foreign_keys = ON",
				"PRAGMA busy_timeout = 5000", // 5 second busy timeout - CRITICAL for preventing SQLITE_BUSY
				"PRAGMA synchronous = NORMAL",
				"PRAGMA cache_size = -64000",
				"PRAGMA temp_store = MEMORY",
			}
			for _, pragma := range pragmas {
				if _, err := conn.ExecContext(context.Background(), pragma, nil); err != nil {
					return fmt.Errorf("failed to set pragma %q: %w", pragma, err)
				}
			}
			return nil
		})
	})
}

// Initialize opens the SQLite database and creates the schema
func Initialize(dbPath string) (*sql.DB, error) {
	// Register connection hook BEFORE opening database
	// This ensures all connections (including pooled ones) get proper pragmas
	registerConnectionHook()

	// Build DSN with _txlock=immediate to ensure all transactions use BEGIN IMMEDIATE.
	// This is critical because:
	// 1. modernc.org/sqlite ignores sql.TxOptions.Isolation - it doesn't translate
	//    sql.LevelSerializable to BEGIN IMMEDIATE as other drivers might
	// 2. Without IMMEDIATE, transactions use BEGIN DEFERRED which acquires locks lazily
	// 3. DEFERRED can cause SQLITE_BUSY_SNAPSHOT (517) errors when upgrading from
	//    SHARED to EXCLUSIVE lock in WAL mode if the database changed between reads
	// 4. IMMEDIATE acquires a RESERVED lock at BEGIN time, preventing upgrade failures
	//
	// Reference: https://pkg.go.dev/modernc.org/sqlite - _txlock parameter
	dsn := dbPath + "?_txlock=immediate"

	// Open database connection
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool to prevent resource exhaustion
	// SQLite with WAL mode benefits from connection pool limits
	db.SetMaxOpenConns(25)                 // Maximum 25 concurrent connections
	db.SetMaxIdleConns(5)                  // Keep 5 idle connections for reuse
	db.SetConnMaxLifetime(5 * time.Minute) // Recycle connections every 5 minutes

	// These pragmas are database-level (persist across connections) and only need
	// to be set once. Connection-level pragmas are set via RegisterConnectionHook above.
	pragmas := []string{
		"PRAGMA journal_mode = WAL",        // Write-Ahead Logging for concurrency (persists)
		"PRAGMA wal_autocheckpoint = 4000", // Checkpoint every 16MB (less frequent)
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma: %w", err)
		}
	}

	// Create schema
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	// Run migration (safe to run multiple times - ALTER TABLE IF NOT EXISTS not supported in SQLite)
	// This will fail silently if column already exists
	db.Exec(migration)

	// Create admin schema
	if _, err := db.Exec(adminSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create admin schema: %w", err)
	}

	// Create user schema
	if _, err := db.Exec(userSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create user schema: %w", err)
	}

	// Run user migration (safe to run multiple times)
	db.Exec(userMigration)

	// Run database migrations
	if err := RunMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}

// BeginImmediateTx starts a transaction with retry logic for robustness.
// The IMMEDIATE locking is ensured by _txlock=immediate in the DSN (set in Initialize()).
//
// Note: The sql.LevelSerializable isolation level is kept for documentation purposes,
// but modernc.org/sqlite ignores it. The actual BEGIN IMMEDIATE behavior comes from
// the _txlock=immediate DSN parameter.
//
// Use this for transactions that will perform writes, especially:
// - Quota check + insert operations
// - Read-modify-write patterns
//
// The function includes retry logic with exponential backoff for handling
// SQLITE_BUSY errors that may still occur during high contention.
func BeginImmediateTx(db *sql.DB) (*sql.Tx, error) {
	return BeginImmediateTxContext(context.Background(), db)
}

// BeginImmediateTxContext is like BeginImmediateTx but accepts a context.
func BeginImmediateTxContext(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	const maxRetries = 5
	baseDelay := 50 * time.Millisecond

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Note: sql.LevelSerializable is specified for documentation, but modernc.org/sqlite
		// ignores this setting. The actual BEGIN IMMEDIATE behavior is controlled by
		// _txlock=immediate in the DSN (set in Initialize()).
		tx, err := db.BeginTx(ctx, &sql.TxOptions{
			Isolation: sql.LevelSerializable,
		})
		if err == nil {
			return tx, nil
		}

		lastErr = err

		// Check if this is a busy/locked error that's worth retrying
		if !isSQLiteBusyError(err) {
			return nil, err // Non-retryable error
		}

		// Wait with exponential backoff before retrying
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt)) // 50ms, 100ms, 200ms, 400ms, 800ms
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	return nil, fmt.Errorf("failed to begin transaction after %d attempts: %w", maxRetries, lastErr)
}

// isSQLiteBusyError checks if an error is an SQLITE_BUSY or SQLITE_LOCKED error.
// SQLite extended error codes:
//   - 5 = SQLITE_BUSY (database is locked)
//   - 6 = SQLITE_LOCKED (table is locked)
//   - 517 = SQLITE_BUSY_SNAPSHOT (WAL mode snapshot conflict)
//   - 262 = SQLITE_BUSY_RECOVERY (WAL recovery in progress)
func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "database is locked") ||
		strings.Contains(errStr, "sqlite_busy") ||
		strings.Contains(errStr, "sqlite_locked") ||
		strings.Contains(errStr, "(5)") ||   // SQLITE_BUSY
		strings.Contains(errStr, "(6)") ||   // SQLITE_LOCKED
		strings.Contains(errStr, "(517)") || // SQLITE_BUSY_SNAPSHOT (WAL mode)
		strings.Contains(errStr, "(262)")    // SQLITE_BUSY_RECOVERY
}
