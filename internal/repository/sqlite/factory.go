package sqlite

import (
	"context"
	"database/sql"
	"log/slog"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// NewRepositories creates all SQLite repository implementations.
// The cfg parameter is included for consistency with other database backends.
// The db parameter must be a valid, open database connection.
//
// Returns the repositories struct with DatabaseType set to "sqlite" and
// a Cleanup function that closes the database connection.
func NewRepositories(cfg *config.Config, db *sql.DB) (*repository.Repositories, error) {
	if db == nil {
		return nil, repository.ErrNilDatabase
	}

	// Handle nil config gracefully for testing scenarios
	dbPath := ""
	if cfg != nil {
		dbPath = cfg.DBPath
	}

	// T43: canonicalize any blocked_ips rows left over from before IP
	// canonicalization existed (or written by an older client). Idempotent
	// and cheap (the blocklist is small), so it's safe to run on every
	// startup rather than gating it behind a one-shot migration flag. Best
	// effort: a failure here shouldn't prevent the app from starting, but
	// (code-review follow-up correcting an earlier, inaccurate version of
	// this comment) it's not fully harmless either. A CIDR row is
	// self-correcting: loadCIDRPrefixes canonicalizes every CIDR-shaped row
	// itself at read time, so containment checks work correctly even
	// against an un-normalized row. A bare-address row is NOT
	// self-correcting: IsIPBlocked's exact-match query only canonicalizes
	// the incoming client IP, not the stored row, so a row left stored
	// non-canonically (e.g. "2001:DB8::1" instead of "2001:db8::1") simply
	// won't match a canonical client IP until either this normalization
	// succeeds or the row is fixed by hand.
	// UnblockIP's exact-string-input fallback still lets such a row be
	// removed by its literal stored value in the meantime.
	if err := NormalizeBlockedIPs(context.Background(), db); err != nil {
		slog.Error("failed to normalize blocked IP entries at startup", "error", err)
	}

	return &repository.Repositories{
		Files:           NewFileRepository(db),
		Users:           NewUserRepository(db),
		Admin:           NewAdminRepository(db),
		Settings:        NewSettingsRepository(db),
		PartialUploads:  NewPartialUploadRepository(db),
		Webhooks:        NewWebhookRepository(db),
		APITokens:       NewAPITokenRepository(db),
		RateLimits:      NewRateLimitRepository(db),
		Locks:           NewLockRepository(db),
		Health:          NewHealthRepository(db, dbPath),
		BackupScheduler: NewBackupSchedulerRepository(db),
		MFA:             NewMFARepository(db),
		SSO:             NewSSORepository(db),
		DB:              db, // DEPRECATED: for backward compatibility during migration
		DatabaseType:    repository.DatabaseTypeSQLite,
		Cleanup: func() {
			db.Close()
		},
	}, nil
}
