package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is a pre-generated valid bcrypt hash used for timing attack mitigation.
// This ensures constant-time behavior when checking credentials for non-existent users.
// Hash of "dummy-password-for-timing-attack-prevention" with cost 12.
const dummyBcryptHash = "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4UWYz/XLKF0S3dCy"

// AdminRepository implements repository.AdminRepository for SQLite.
type AdminRepository struct {
	db *sql.DB
}

// NewAdminRepository creates a new SQLite admin repository.
func NewAdminRepository(db *sql.DB) *AdminRepository {
	return &AdminRepository{db: db}
}

// ValidateCredentials checks if the provided username and password are valid.
// Returns true if valid, false if invalid.
//
// SECURITY: Uses bcrypt constant-time comparison. Does not differentiate between
// "user not found" and "wrong password" to prevent user enumeration.
func (r *AdminRepository) ValidateCredentials(ctx context.Context, username, password string) (bool, error) {
	query := `SELECT password_hash FROM admin_credentials WHERE username = ?`

	var hashedPassword string
	err := r.db.QueryRowContext(ctx, query, username).Scan(&hashedPassword)

	if err == sql.ErrNoRows {
		// User not found - perform a dummy bcrypt comparison to prevent timing attacks
		// that could reveal whether the username exists.
		// Uses a valid pre-generated hash to ensure full bcrypt comparison runs.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password)) //nolint:errcheck // Intentional: timing attack mitigation
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("credential validation failed: %w", err)
	}

	// Constant-time comparison using bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, nil // Invalid password
	}

	return true, nil
}

// InitializeCredentials creates or updates admin credentials in the database.
// The password parameter is plaintext and will be hashed using bcrypt with cost 12.
//
// SECURITY: Plaintext password is never stored or logged.
// Uses UPSERT pattern for atomic operation to prevent race conditions.
func (r *AdminRepository) InitializeCredentials(ctx context.Context, username, password string) error {
	// Validate inputs
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	// bcrypt silently truncates at 72 bytes - warn/reject if longer
	if len(password) > 72 {
		return fmt.Errorf("password cannot exceed 72 characters (bcrypt limitation)")
	}

	// Hash the password with bcrypt cost 12 (security requirement)
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	hashedPassword := string(hashedBytes)

	// Use UPSERT pattern for atomic operation to prevent race conditions
	// This ensures only one admin credential row exists (id=1)
	query := `INSERT INTO admin_credentials (id, username, password_hash) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash`
	_, err = r.db.ExecContext(ctx, query, username, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to initialize admin credentials: %w", err)
	}

	slog.Info("admin credentials initialized/updated", "username", username)
	return nil
}

// CreateSession creates a new admin session.
func (r *AdminRepository) CreateSession(ctx context.Context, token string, expiresAt time.Time, ipAddress, userAgent string) error {
	query := `INSERT INTO admin_sessions (session_token, expires_at, ip_address, user_agent)
		VALUES (?, ?, ?, ?)`

	// Format as RFC3339 for consistent SQLite datetime parsing
	expiresAtRFC3339 := expiresAt.Format(time.RFC3339)

	_, err := r.db.ExecContext(ctx, query, token, expiresAtRFC3339, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to create admin session: %w", err)
	}

	return nil
}

// GetSession retrieves a session by token.
// Returns nil, nil if the session doesn't exist or is expired.
func (r *AdminRepository) GetSession(ctx context.Context, token string) (*repository.AdminSession, error) {
	// Note: datetime(expires_at) normalizes RFC3339 format for proper comparison
	query := `SELECT id, session_token, created_at, expires_at, last_activity, ip_address, user_agent
		FROM admin_sessions WHERE session_token = ? AND datetime(expires_at) > datetime('now')`

	var session repository.AdminSession
	var createdAt, expiresAt, lastActivity string

	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID,
		&session.SessionToken,
		&createdAt,
		&expiresAt,
		&lastActivity,
		&session.IPAddress,
		&session.UserAgent,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get admin session: %w", err)
	}

	// Parse timestamps
	session.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	session.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	session.LastActivity, err = time.Parse(time.RFC3339, lastActivity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse last_activity: %w", err)
	}

	return &session, nil
}

// UpdateSessionActivity updates the last activity timestamp for a session.
func (r *AdminRepository) UpdateSessionActivity(ctx context.Context, token string) error {
	query := `UPDATE admin_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_token = ?`

	_, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to update admin session activity: %w", err)
	}

	return nil
}

// DeleteSession deletes a session (logout).
func (r *AdminRepository) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM admin_sessions WHERE session_token = ?`

	_, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete admin session: %w", err)
	}

	return nil
}

// CleanupExpiredSessions removes expired admin sessions.
func (r *AdminRepository) CleanupExpiredSessions(ctx context.Context) error {
	// Note: datetime(expires_at) normalizes RFC3339 format for proper comparison
	query := `DELETE FROM admin_sessions WHERE datetime(expires_at) < datetime('now')`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired admin sessions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		slog.Debug("cleaned up expired admin sessions", "count", rowsAffected)
	}

	return nil
}

// BlockIP adds an IP address to the blocklist.
func (r *AdminRepository) BlockIP(ctx context.Context, ipAddress, reason, blockedBy string) error {
	// Validate IP address format
	if ipAddress == "" {
		return fmt.Errorf("IP address cannot be empty")
	}

	// Validate it's a proper IPv4 or IPv6 address
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid IP address format")
	}

	query := `INSERT INTO blocked_ips (ip_address, reason, blocked_by)
		VALUES (?, ?, ?)`

	_, err := r.db.ExecContext(ctx, query, ipAddress, reason, blockedBy)
	if err != nil {
		return fmt.Errorf("failed to block IP: %w", err)
	}

	slog.Info("IP blocked", "ip", ipAddress, "reason", reason, "blocked_by", blockedBy)
	return nil
}

// UnblockIP removes an IP address from the blocklist.
// Returns ErrNotFound if the IP is not in the blocklist.
func (r *AdminRepository) UnblockIP(ctx context.Context, ipAddress string) error {
	query := `DELETE FROM blocked_ips WHERE ip_address = ?`

	result, err := r.db.ExecContext(ctx, query, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to unblock IP: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	slog.Info("IP unblocked", "ip", ipAddress)
	return nil
}

// IsIPBlocked checks if an IP address is blocked.
// Returns (isBlocked, error).
func (r *AdminRepository) IsIPBlocked(ctx context.Context, ipAddress string) (bool, error) {
	query := `SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ?`

	var count int
	err := r.db.QueryRowContext(ctx, query, ipAddress).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check if IP is blocked: %w", err)
	}

	return count > 0, nil
}

// GetBlockedIPs retrieves all blocked IP addresses.
func (r *AdminRepository) GetBlockedIPs(ctx context.Context) ([]repository.BlockedIP, error) {
	query := `SELECT id, ip_address, reason, blocked_at, blocked_by
		FROM blocked_ips ORDER BY blocked_at DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query blocked IPs: %w", err)
	}
	defer rows.Close()

	var blockedIPs []repository.BlockedIP
	for rows.Next() {
		var ip repository.BlockedIP
		var blockedAt string

		err := rows.Scan(&ip.ID, &ip.IPAddress, &ip.Reason, &blockedAt, &ip.BlockedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blocked IP: %w", err)
		}

		// Parse timestamp
		ip.BlockedAt, err = time.Parse(time.RFC3339, blockedAt)
		if err != nil {
			// Try alternate format from SQLite
			ip.BlockedAt, err = time.Parse("2006-01-02 15:04:05", blockedAt)
			if err != nil {
				return nil, fmt.Errorf("failed to parse blocked_at: %w", err)
			}
		}

		blockedIPs = append(blockedIPs, ip)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating blocked IPs: %w", err)
	}

	return blockedIPs, nil
}

// Ensure AdminRepository implements repository.AdminRepository.
var _ repository.AdminRepository = (*AdminRepository)(nil)
