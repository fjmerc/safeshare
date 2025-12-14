package postgres

import (
	"context"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HealthRepository implements health checks for PostgreSQL databases.
type HealthRepository struct {
	pool *pgxpool.Pool
}

// NewHealthRepository creates a new PostgreSQL health repository.
func NewHealthRepository(pool *pgxpool.Pool) *HealthRepository {
	return &HealthRepository{pool: pool}
}

// Ping performs a basic connectivity check to the database.
// For PostgreSQL, this pings the connection pool.
func (r *HealthRepository) Ping(ctx context.Context) error {
	return r.pool.Ping(ctx)
}

// CheckHealth performs a comprehensive health check for PostgreSQL.
func (r *HealthRepository) CheckHealth(ctx context.Context) (*repository.ComponentHealth, error) {
	start := time.Now()
	health := &repository.ComponentHealth{
		Name:   "postgresql",
		Status: repository.HealthStatusHealthy,
	}

	// Test with a simple query
	var result int
	err := r.pool.QueryRow(ctx, "SELECT 1").Scan(&result)
	health.Latency = time.Since(start)

	if err != nil {
		health.Status = repository.HealthStatusUnhealthy
		health.Message = "database query failed: " + err.Error()
		return health, err
	}

	if result != 1 {
		health.Status = repository.HealthStatusUnhealthy
		health.Message = "unexpected query result"
		return health, nil
	}

	// Check if latency is too high
	if health.Latency > 100*time.Millisecond {
		health.Status = repository.HealthStatusDegraded
		health.Message = "high query latency"
	}

	return health, nil
}

// GetDatabaseStats returns PostgreSQL-specific statistics.
func (r *HealthRepository) GetDatabaseStats(ctx context.Context) (map[string]any, error) {
	stats := make(map[string]any)

	// Get database size
	var dbSize int64
	err := r.pool.QueryRow(ctx, "SELECT pg_database_size(current_database())").Scan(&dbSize)
	if err != nil {
		return nil, err
	}
	stats["size_bytes"] = dbSize
	stats["size_mb"] = float64(dbSize) / 1024 / 1024

	// Get connection count
	var connections int64
	err = r.pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()").Scan(&connections)
	if err != nil {
		return nil, err
	}
	stats["active_connections"] = connections

	// Get pool stats
	poolStats := r.pool.Stat()
	stats["pool_acquired_conns"] = poolStats.AcquiredConns()
	stats["pool_idle_conns"] = poolStats.IdleConns()
	stats["pool_total_conns"] = poolStats.TotalConns()
	stats["pool_max_conns"] = poolStats.MaxConns()
	stats["pool_acquire_count"] = poolStats.AcquireCount()
	stats["pool_acquire_duration_ms"] = poolStats.AcquireDuration().Milliseconds()

	// Get table count
	var tableCount int64
	err = r.pool.QueryRow(ctx, `
		SELECT count(*) 
		FROM information_schema.tables 
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
	`).Scan(&tableCount)
	if err != nil {
		return nil, err
	}
	stats["table_count"] = tableCount

	// Get index count
	var indexCount int64
	err = r.pool.QueryRow(ctx, `
		SELECT count(*) 
		FROM pg_indexes 
		WHERE schemaname = 'public'
	`).Scan(&indexCount)
	if err != nil {
		return nil, err
	}
	stats["index_count"] = indexCount

	return stats, nil
}
