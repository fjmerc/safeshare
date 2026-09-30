package main

import (
	"fmt"

	"github.com/fjmerc/safeshare/internal/config"
)

// requireWiredBackends refuses to start when the configuration selects a
// database or storage backend this binary does not actually use.
//
// The config package accepts and validates DATABASE_TYPE=postgresql and
// STORAGE_TYPE=s3, and repository/storage implementations for both exist,
// but run() always builds a SQLite repository set and filesystem storage.
// Starting anyway would silently keep every file and record on local disk
// while the operator believes they live in PostgreSQL/S3, so fail closed
// until those backends are wired into this entry point (audit T44).
func requireWiredBackends(cfg *config.Config) error {
	if cfg.DatabaseType != "" && cfg.DatabaseType != "sqlite" {
		return fmt.Errorf("DATABASE_TYPE=%s is not supported by this server yet (only sqlite is wired in); "+
			"unset DATABASE_TYPE or set it to sqlite", cfg.DatabaseType)
	}
	if cfg.StorageType != "" && cfg.StorageType != "filesystem" {
		return fmt.Errorf("STORAGE_TYPE=%s is not supported by this server yet (only filesystem is wired in); "+
			"unset STORAGE_TYPE or set it to filesystem", cfg.StorageType)
	}
	return nil
}
