package repository

import (
	"context"
	"time"
)

// HealthStatus represents the overall health state.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// ComponentHealth represents the health of a single component.
type ComponentHealth struct {
	Name    string        `json:"name"`
	Status  HealthStatus  `json:"status"`
	Latency time.Duration `json:"latency_ms,omitempty"`
	Message string        `json:"message,omitempty"`
}

// HealthCheckResult contains detailed health information.
type HealthCheckResult struct {
	Status     HealthStatus       `json:"status"`
	Components []ComponentHealth  `json:"components,omitempty"`
	Details    map[string]any     `json:"details,omitempty"`
}

// HealthRepository provides health check operations for the database.
type HealthRepository interface {
	// Ping performs a basic connectivity check to the database.
	// This should be fast (< 10ms) for liveness probes.
	Ping(ctx context.Context) error

	// CheckHealth performs a more comprehensive health check.
	// This includes verifying the database is responsive and can execute queries.
	CheckHealth(ctx context.Context) (*ComponentHealth, error)

	// GetDatabaseStats returns database-specific statistics for monitoring.
	// Returns nil if stats are not available for the database type.
	GetDatabaseStats(ctx context.Context) (map[string]any, error)
}
