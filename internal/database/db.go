package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
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
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

// Initialize opens the SQLite database and creates the schema
func Initialize(dbPath string) (*sql.DB, error) {
	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Enable foreign keys and WAL mode for better concurrency
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000", // 64MB cache
		"PRAGMA busy_timeout = 5000",  // 5 second busy timeout
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

	return db, nil
}
