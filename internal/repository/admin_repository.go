package repository

import (
	"context"
	"time"
)

// AdminRepository defines the interface for admin-related database operations.
// All methods accept a context for cancellation and timeout support.
type AdminRepository interface {
	// Credential operations

	// ValidateCredentials checks if the provided username and password are valid.
	// Returns true if valid, false if invalid.
	//
	// SECURITY REQUIREMENTS for implementations:
	// - MUST use bcrypt.CompareHashAndPassword or equivalent constant-time comparison
	// - MUST NOT log the password parameter under any circumstances
	// - MUST NOT differentiate between "user not found" and "wrong password" in errors
	ValidateCredentials(ctx context.Context, username, password string) (bool, error)

	// InitializeCredentials creates or updates admin credentials in the database.
	// The password parameter is plaintext and MUST be hashed by the implementation
	// using bcrypt with cost >= 12 before storage.
	//
	// SECURITY: Implementation MUST NOT store or log the plaintext password.
	InitializeCredentials(ctx context.Context, username, password string) error

	// Session operations

	// CreateSession creates a new admin session.
	CreateSession(ctx context.Context, token string, expiresAt time.Time, ipAddress, userAgent string) error

	// GetSession retrieves a session by token.
	// Returns nil, nil if the session doesn't exist or is expired.
	GetSession(ctx context.Context, token string) (*AdminSession, error)

	// UpdateSessionActivity updates the last activity timestamp for a session.
	UpdateSessionActivity(ctx context.Context, token string) error

	// DeleteSession deletes a session (logout).
	DeleteSession(ctx context.Context, token string) error

	// CleanupExpiredSessions removes expired admin sessions.
	CleanupExpiredSessions(ctx context.Context) error

	// IP blocking operations

	// BlockIP adds an IP address to the blocklist.
	BlockIP(ctx context.Context, ipAddress, reason, blockedBy string) error

	// UnblockIP removes an IP address from the blocklist.
	// Returns ErrNotFound if the IP is not in the blocklist.
	UnblockIP(ctx context.Context, ipAddress string) error

	// IsIPBlocked checks if an IP address is blocked.
	// Returns (isBlocked, error).
	IsIPBlocked(ctx context.Context, ipAddress string) (bool, error)

	// GetBlockedIPs retrieves all blocked IP addresses.
	GetBlockedIPs(ctx context.Context) ([]BlockedIP, error)
}
