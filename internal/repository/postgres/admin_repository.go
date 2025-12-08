// Package postgres provides PostgreSQL implementations of repository interfaces.
package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is a pre-generated valid bcrypt hash used for timing attack mitigation.
// This ensures constant-time behavior when checking credentials for non-existent users.
// Hash of "dummy-password-for-timing-attack-prevention" with cost 12.
const dummyBcryptHash = "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4UWYz/XLKF0S3dCy"

// AdminRepository implements repository.AdminRepository for PostgreSQL.
type AdminRepository struct {
	pool *Pool
}

// NewAdminRepository creates a new PostgreSQL admin repository.
func NewAdminRepository(pool *Pool) *AdminRepository {
	return &AdminRepository{pool: pool}
}

// ValidateCredentials checks if the provided username and password are valid.
// Returns true if valid, false if invalid.
//
// SECURITY: Uses bcrypt constant-time comparison. Does not differentiate between
// "user not found" and "wrong password" to prevent user enumeration.
func (r *AdminRepository) ValidateCredentials(ctx context.Context, username, password string) (bool, error) {
	query := `SELECT password_hash FROM admin_credentials WHERE username = $1`

	var hashedPassword string
	err := r.pool.QueryRow(ctx, query, username).Scan(&hashedPassword)

	if err == pgx.ErrNoRows {
		// User not found - perform a dummy bcrypt comparison to prevent timing attacks
		bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password))
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

	// Hash the password with bcrypt cost 12
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	hashedPassword := string(hashedBytes)

	// Use UPSERT pattern for atomic operation
	query := `
		INSERT INTO admin_credentials (id, username, password_hash) 
		VALUES (1, $1, $2)
		ON CONFLICT (id) DO UPDATE SET 
			username = EXCLUDED.username, 
			password_hash = EXCLUDED.password_hash,
			updated_at = NOW()
	`
	_, err = r.pool.Exec(ctx, query, username, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to initialize admin credentials: %w", err)
	}

	slog.Info("admin credentials initialized/updated", "username", username)
	return nil
}

// CreateSession creates a new admin session.
func (r *AdminRepository) CreateSession(ctx context.Context, token string, expiresAt time.Time, ipAddress, userAgent string) error {
	query := `
		INSERT INTO admin_sessions (session_token, expires_at, ip_address, user_agent)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.pool.Exec(ctx, query, token, expiresAt, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to create admin session: %w", err)
	}

	return nil
}

// GetSession retrieves a session by token.
// Returns nil, nil if the session doesn't exist or is expired.
func (r *AdminRepository) GetSession(ctx context.Context, token string) (*repository.AdminSession, error) {
	query := `
		SELECT id, session_token, created_at, expires_at, last_activity, ip_address, user_agent
		FROM admin_sessions 
		WHERE session_token = $1 AND expires_at > NOW()
	`

	var session repository.AdminSession

	err := r.pool.QueryRow(ctx, query, token).Scan(
		&session.ID,
		&session.SessionToken,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.LastActivity,
		&session.IPAddress,
		&session.UserAgent,
	)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get admin session: %w", err)
	}

	return &session, nil
}

// UpdateSessionActivity updates the last activity timestamp for a session.
func (r *AdminRepository) UpdateSessionActivity(ctx context.Context, token string) error {
	query := `UPDATE admin_sessions SET last_activity = NOW() WHERE session_token = $1`

	_, err := r.pool.Exec(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to update admin session activity: %w", err)
	}

	return nil
}

// DeleteSession deletes a session (logout).
func (r *AdminRepository) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM admin_sessions WHERE session_token = $1`

	_, err := r.pool.Exec(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete admin session: %w", err)
	}

	return nil
}

// CleanupExpiredSessions removes expired admin sessions.
func (r *AdminRepository) CleanupExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM admin_sessions WHERE expires_at < NOW()`

	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired admin sessions: %w", err)
	}

	if result.RowsAffected() > 0 {
		slog.Debug("cleaned up expired admin sessions", "count", result.RowsAffected())
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

	query := `
		INSERT INTO blocked_ips (ip_address, reason, blocked_by)
		VALUES ($1, $2, $3)
	`

	_, err := r.pool.Exec(ctx, query, ipAddress, reason, blockedBy)
	if err != nil {
		if isUniqueViolation(err) {
			return repository.ErrDuplicateKey
		}
		return fmt.Errorf("failed to block IP: %w", err)
	}

	slog.Info("IP blocked", "ip", ipAddress, "reason", reason, "blocked_by", blockedBy)
	return nil
}

// UnblockIP removes an IP address from the blocklist.
// Returns ErrNotFound if the IP is not in the blocklist.
func (r *AdminRepository) UnblockIP(ctx context.Context, ipAddress string) error {
	query := `DELETE FROM blocked_ips WHERE ip_address = $1`

	result, err := r.pool.Exec(ctx, query, ipAddress)
	if err != nil {
		return fmt.Errorf("failed to unblock IP: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	slog.Info("IP unblocked", "ip", ipAddress)
	return nil
}

// IsIPBlocked checks if an IP address is blocked.
// Returns (isBlocked, error).
func (r *AdminRepository) IsIPBlocked(ctx context.Context, ipAddress string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM blocked_ips WHERE ip_address = $1)`

	var exists bool
	err := r.pool.QueryRow(ctx, query, ipAddress).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if IP is blocked: %w", err)
	}

	return exists, nil
}

// GetBlockedIPs retrieves all blocked IP addresses.
// Limited to 10000 results to prevent memory exhaustion.
func (r *AdminRepository) GetBlockedIPs(ctx context.Context) ([]repository.BlockedIP, error) {
	query := `
		SELECT id, ip_address, reason, blocked_at, blocked_by
		FROM blocked_ips 
		ORDER BY blocked_at DESC
		LIMIT 10000
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query blocked IPs: %w", err)
	}
	defer rows.Close()

	var blockedIPs []repository.BlockedIP
	for rows.Next() {
		var ip repository.BlockedIP

		err := rows.Scan(&ip.ID, &ip.IPAddress, &ip.Reason, &ip.BlockedAt, &ip.BlockedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blocked IP: %w", err)
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
