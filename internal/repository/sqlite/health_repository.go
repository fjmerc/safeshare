package sqlite

import (
	"context"
	"database/sql"
	"os"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// HealthRepository implements health checks for SQLite databases.
type HealthRepository struct {
	db     *sql.DB
	dbPath string
}

// NewHealthRepository creates a new SQLite health repository.
func NewHealthRepository(db *sql.DB, dbPath string) *HealthRepository {
	return &HealthRepository{
		db:     db,
		dbPath: dbPath,
	}
}

// Ping performs a basic connectivity check to the database.
// For SQLite, this pings the database connection pool.
func (r *HealthRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

// CheckHealth performs a comprehensive health check for SQLite.
func (r *HealthRepository) CheckHealth(ctx context.Context) (*repository.ComponentHealth, error) {
	start := time.Now()
	health := &repository.ComponentHealth{
		Name:   "sqlite",
		Status: repository.HealthStatusHealthy,
	}

	// Test with a simple query
	var result int
	err := r.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
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

	// Check if latency is too high (potential lock contention)
	if health.Latency > 100*time.Millisecond {
		health.Status = repository.HealthStatusDegraded
		health.Message = "high query latency"
	}

	return health, nil
}

// GetDatabaseStats returns SQLite-specific statistics.
func (r *HealthRepository) GetDatabaseStats(ctx context.Context) (map[string]any, error) {
	stats := make(map[string]any)

	// Get page count and page size
	var pageCount, pageSize int64
	if err := r.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return nil, err
	}
	if err := r.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return nil, err
	}

	stats["page_count"] = pageCount
	stats["page_size"] = pageSize
	stats["size_bytes"] = pageCount * pageSize
	stats["size_mb"] = float64(pageCount*pageSize) / 1024 / 1024

	// Get index count
	var indexCount int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='index'").Scan(&indexCount); err != nil {
		return nil, err
	}
	stats["index_count"] = indexCount

	// Get WAL file size if it exists
	walPath := r.dbPath + "-wal"
	if info, err := os.Stat(walPath); err == nil {
		stats["wal_size_bytes"] = info.Size()
	}

	// Get connection pool stats
	dbStats := r.db.Stats()
	stats["pool_open_connections"] = dbStats.OpenConnections
	stats["pool_in_use"] = dbStats.InUse
	stats["pool_idle"] = dbStats.Idle
	stats["pool_wait_count"] = dbStats.WaitCount
	stats["pool_wait_duration_ms"] = dbStats.WaitDuration.Milliseconds()

	return stats, nil
}
