package database

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migration represents a database migration
type Migration struct {
	ID      int
	Name    string
	Applied bool
}

const migrationsTableSchema = `
CREATE TABLE IF NOT EXISTS migrations (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_migrations_name ON migrations(name);
`

// RunMigrations applies all pending database migrations
func RunMigrations(db *sql.DB) error {
	slog.Info("running database migrations")

	// Create migrations table if it doesn't exist
	if _, err := db.Exec(migrationsTableSchema); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get list of applied migrations
	appliedMigrations, err := getAppliedMigrations(db)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	appliedMap := make(map[string]bool)
	for _, name := range appliedMigrations {
		appliedMap[name] = true
	}

	// Read migration files from embedded filesystem
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Sort migration files by name (ensures 001_, 002_, etc. order)
	var migrationNames []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			migrationNames = append(migrationNames, entry.Name())
		}
	}
	sort.Strings(migrationNames)

	// Apply pending migrations
	pendingCount := 0
	for _, name := range migrationNames {
		if appliedMap[name] {
			slog.Debug("migration already applied", "migration", name)
			continue
		}

		slog.Info("applying migration", "migration", name)

		// Read migration SQL
		sqlBytes, err := migrationFiles.ReadFile(filepath.Join("migrations", name))
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", name, err)
		}

		sqlContent := string(sqlBytes)

		// Execute migration in a transaction
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %s: %w", name, err)
		}

		// Execute migration SQL
		if _, err := tx.Exec(sqlContent); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to execute migration %s: %w", name, err)
		}

		// Record migration as applied
		if _, err := tx.Exec("INSERT INTO migrations (name) VALUES (?)", name); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %s: %w", name, err)
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", name, err)
		}

		slog.Info("migration applied successfully", "migration", name)
		pendingCount++
	}

	if pendingCount == 0 {
		slog.Info("no pending migrations")
	} else {
		slog.Info("migrations complete", "applied", pendingCount)
	}

	return nil
}

// getAppliedMigrations returns a list of already applied migration names
func getAppliedMigrations(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT name FROM migrations ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var migrations []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		migrations = append(migrations, name)
	}

	return migrations, rows.Err()
}

// GetMigrationStatus returns the status of all migrations
func GetMigrationStatus(db *sql.DB) ([]Migration, error) {
	// Get applied migrations
	appliedMigrations, err := getAppliedMigrations(db)
	if err != nil {
		return nil, err
	}

	appliedMap := make(map[string]bool)
	for _, name := range appliedMigrations {
		appliedMap[name] = true
	}

	// Read all migration files
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var migrations []Migration
	id := 1
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			name := entry.Name()
			migrations = append(migrations, Migration{
				ID:      id,
				Name:    name,
				Applied: appliedMap[name],
			})
			id++
		}
	}

	// Sort by name
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Name < migrations[j].Name
	})

	return migrations, nil
}
