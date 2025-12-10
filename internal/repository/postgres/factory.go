package postgres

import (
	"context"
	"fmt"
	"net/url"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// NewRepositories creates all PostgreSQL repository implementations.
// This factory creates a connection pool and all repository instances.
//
// The cfg parameter provides PostgreSQL configuration options.
// Returns the repositories and a cleanup function to close the pool.
func NewRepositories(cfg *config.Config) (*repository.Repositories, func(), error) {
	// Get PostgreSQL config
	pgCfg := cfg.PostgreSQL
	if pgCfg == nil {
		return nil, nil, fmt.Errorf("PostgreSQL configuration is nil")
	}

	// Build connection string
	connStr := buildConnectionString(pgCfg)

	// Create connection pool
	pool, err := NewPool(context.Background(), connStr, int32(pgCfg.MaxConnections))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create PostgreSQL connection pool: %w", err)
	}

	// Run migrations if enabled
	if pgCfg.AutoMigrate {
		if err := RunMigrations(context.Background(), pool); err != nil {
			pool.Close()
			return nil, nil, fmt.Errorf("failed to run PostgreSQL migrations: %w", err)
		}
	}

	// Create cleanup function
	cleanup := func() {
		pool.Close()
	}

	// Create all repositories
	repos := &repository.Repositories{
		Files:           NewFileRepository(pool),
		Users:           NewUserRepository(pool),
		Admin:           NewAdminRepository(pool),
		Settings:        NewSettingsRepository(pool),
		PartialUploads:  NewPartialUploadRepository(pool),
		Webhooks:        NewWebhookRepository(pool),
		APITokens:       NewAPITokenRepository(pool),
		RateLimits:      NewRateLimitRepository(pool),
		Locks:           NewLockRepository(pool),
		Health:          NewHealthRepository(pool.Pool),
		BackupScheduler: NewBackupSchedulerRepository(pool),
		MFA:             NewMFARepository(pool),
		SSO:             NewSSORepository(pool),
		DB:              nil, // PostgreSQL doesn't use *sql.DB
		DatabaseType:    repository.DatabaseTypePostgreSQL,
		Cleanup:         cleanup,
	}

	return repos, cleanup, nil
}

// NewRepositoriesWithPool creates all PostgreSQL repository implementations using an existing pool.
// This is useful for testing or when the pool needs to be created separately.
// Note: The caller is responsible for closing the pool; Cleanup will be nil.
func NewRepositoriesWithPool(pool *Pool) (*repository.Repositories, error) {
	if pool == nil {
		return nil, repository.ErrNilDatabase
	}

	return &repository.Repositories{
		Files:           NewFileRepository(pool),
		Users:           NewUserRepository(pool),
		Admin:           NewAdminRepository(pool),
		Settings:        NewSettingsRepository(pool),
		PartialUploads:  NewPartialUploadRepository(pool),
		Webhooks:        NewWebhookRepository(pool),
		APITokens:       NewAPITokenRepository(pool),
		RateLimits:      NewRateLimitRepository(pool),
		Locks:           NewLockRepository(pool),
		Health:          NewHealthRepository(pool.Pool),
		BackupScheduler: NewBackupSchedulerRepository(pool),
		MFA:             NewMFARepository(pool),
		SSO:             NewSSORepository(pool),
		DB:              nil, // PostgreSQL doesn't use *sql.DB
		DatabaseType:    repository.DatabaseTypePostgreSQL,
		Cleanup:         nil, // Caller manages the pool lifecycle
	}, nil
}

// buildConnectionString constructs a PostgreSQL connection string from config.
// Credentials are URL-encoded to handle special characters safely.
func buildConnectionString(cfg *config.PostgreSQLConfig) string {
	// Build connection string
	// Format: postgres://user:password@host:port/dbname?sslmode=mode
	// URL-encode user and password to handle special characters (@, :, /, etc.)
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		url.PathEscape(cfg.User),
		url.PathEscape(cfg.Password),
		cfg.Host,
		cfg.Port,
		cfg.Database,
	)

	// Add SSL mode
	sslMode := cfg.SSLMode
	if sslMode == "" {
		sslMode = "prefer" // Default to prefer SSL
	}
	connStr += fmt.Sprintf("?sslmode=%s", sslMode)

	// Add additional options if provided
	if cfg.Options != "" {
		connStr += "&" + cfg.Options
	}

	return connStr
}
