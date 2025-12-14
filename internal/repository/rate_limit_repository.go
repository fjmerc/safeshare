package repository

import (
	"context"
	"time"
)

// RateLimitEntry represents a rate limit record for an IP/limit type combination.
type RateLimitEntry struct {
	ID        int64
	IPAddress string
	LimitType string    // "upload", "download", "chunk", "regeneration", "admin_login", "user_login"
	Count     int       // Number of requests in the current window
	WindowEnd time.Time // When the current window expires
	CreatedAt time.Time
	UpdatedAt time.Time
}

// RateLimitRepository defines the interface for database-backed rate limiting.
// This enables multi-node deployments where rate limits are shared across instances.
type RateLimitRepository interface {
	// IncrementAndCheck atomically increments the request count for an IP/type combination
	// and returns whether the request should be allowed based on the limit.
	// If the window has expired, it resets the counter.
	//
	// Parameters:
	// - ctx: Context for cancellation and timeout
	// - ipAddress: The client IP address
	// - limitType: Type of limit (e.g., "upload", "download", "admin_login")
	// - limit: Maximum allowed requests in the window
	// - windowDuration: Duration of the rate limit window
	//
	// Returns:
	// - allowed: true if request is within limits, false if exceeded
	// - currentCount: current number of requests in this window
	// - error: any database error
	IncrementAndCheck(ctx context.Context, ipAddress, limitType string, limit int, windowDuration time.Duration) (allowed bool, currentCount int, err error)

	// GetEntry retrieves the rate limit entry for an IP/type combination.
	// Returns nil, nil if no entry exists.
	GetEntry(ctx context.Context, ipAddress, limitType string) (*RateLimitEntry, error)

	// ResetEntry resets the rate limit for an IP/type combination.
	// Useful for testing or admin override.
	ResetEntry(ctx context.Context, ipAddress, limitType string) error

	// CleanupExpired removes rate limit entries that have expired.
	// Should be called periodically by a cleanup worker.
	// Returns the number of entries removed.
	CleanupExpired(ctx context.Context) (int64, error)

	// GetAllEntriesForIP retrieves all rate limit entries for a given IP.
	// Useful for debugging and admin dashboard.
	GetAllEntriesForIP(ctx context.Context, ipAddress string) ([]RateLimitEntry, error)
}
