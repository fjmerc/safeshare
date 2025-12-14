// Package repository provides interfaces for data access.
package repository

import (
	"context"
	"time"
)

// BackupTriggerType represents how a backup was triggered.
type BackupTriggerType string

const (
	// BackupTriggerManual indicates the backup was triggered manually via UI or CLI.
	BackupTriggerManual BackupTriggerType = "manual"

	// BackupTriggerScheduled indicates the backup was triggered by the scheduler.
	BackupTriggerScheduled BackupTriggerType = "scheduled"

	// BackupTriggerAPI indicates the backup was triggered via API call.
	BackupTriggerAPI BackupTriggerType = "api"
)

// BackupRunStatus represents the status of a backup run.
type BackupRunStatus string

const (
	// BackupRunStatusPending indicates the backup is queued but not started.
	BackupRunStatusPending BackupRunStatus = "pending"

	// BackupRunStatusRunning indicates the backup is currently executing.
	BackupRunStatusRunning BackupRunStatus = "running"

	// BackupRunStatusCompleted indicates the backup completed successfully.
	BackupRunStatusCompleted BackupRunStatus = "completed"

	// BackupRunStatusFailed indicates the backup failed.
	BackupRunStatusFailed BackupRunStatus = "failed"
)

// BackupSchedule represents a scheduled backup configuration.
type BackupSchedule struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Enabled       bool       `json:"enabled"`
	Schedule      string     `json:"schedule"`        // Cron expression
	Mode          string     `json:"mode"`            // full, database, config
	RetentionDays int        `json:"retention_days"`  // Days to keep backups (0=unlimited)
	LastRunAt     *time.Time `json:"last_run_at"`     // Last execution time
	NextRunAt     *time.Time `json:"next_run_at"`     // Next scheduled execution
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// BackupRun represents a single backup execution.
type BackupRun struct {
	ID             int64             `json:"id"`
	ScheduleID     *int64            `json:"schedule_id"`      // NULL for manual backups
	TriggerType    BackupTriggerType `json:"trigger_type"`
	Status         BackupRunStatus   `json:"status"`
	Mode           string            `json:"mode"`             // full, database, config
	OutputPath     string            `json:"output_path"`      // Path to backup directory
	SizeBytes      int64             `json:"size_bytes"`       // Total backup size
	FilesBackedUp  int               `json:"files_backed_up"`  // Number of files
	ErrorMessage   string            `json:"error_message"`    // Error if failed
	StartedAt      time.Time         `json:"started_at"`
	CompletedAt    *time.Time        `json:"completed_at"`
	DurationMs     int               `json:"duration_ms"`      // Duration in milliseconds
}

// BackupRunFilter specifies filter criteria for listing backup runs.
type BackupRunFilter struct {
	ScheduleID  *int64           // Filter by schedule
	Status      *BackupRunStatus // Filter by status
	TriggerType *BackupTriggerType // Filter by trigger type
	Limit       int              // Max results (default 100)
	Offset      int              // Pagination offset
}

// BackupSchedulerRepository provides access to backup schedule and run data.
type BackupSchedulerRepository interface {
	// === Schedule Management ===

	// CreateSchedule creates a new backup schedule.
	CreateSchedule(ctx context.Context, schedule *BackupSchedule) error

	// GetSchedule retrieves a schedule by ID.
	GetSchedule(ctx context.Context, id int64) (*BackupSchedule, error)

	// GetScheduleByName retrieves a schedule by name.
	GetScheduleByName(ctx context.Context, name string) (*BackupSchedule, error)

	// UpdateSchedule updates an existing schedule.
	UpdateSchedule(ctx context.Context, schedule *BackupSchedule) error

	// DeleteSchedule deletes a schedule by ID.
	DeleteSchedule(ctx context.Context, id int64) error

	// ListSchedules returns all schedules.
	ListSchedules(ctx context.Context) ([]BackupSchedule, error)

	// GetDueSchedules returns enabled schedules that are due for execution.
	// A schedule is due if next_run_at is <= now.
	GetDueSchedules(ctx context.Context, now time.Time) ([]BackupSchedule, error)

	// UpdateScheduleLastRun updates the last_run_at and next_run_at fields.
	UpdateScheduleLastRun(ctx context.Context, id int64, lastRunAt time.Time, nextRunAt time.Time) error

	// === Backup Run Management ===

	// CreateRun creates a new backup run record.
	CreateRun(ctx context.Context, run *BackupRun) error

	// GetRun retrieves a run by ID.
	GetRun(ctx context.Context, id int64) (*BackupRun, error)

	// UpdateRun updates an existing run (typically status, output_path, error_message).
	UpdateRun(ctx context.Context, run *BackupRun) error

	// CompleteRun marks a run as completed or failed.
	// Sets completed_at, duration_ms, status, and optionally error_message.
	CompleteRun(ctx context.Context, id int64, status BackupRunStatus, outputPath string, sizeBytes int64, filesBackedUp int, errorMessage string) error

	// ListRuns returns runs matching the filter criteria.
	ListRuns(ctx context.Context, filter BackupRunFilter) ([]BackupRun, error)

	// GetLastRunForSchedule returns the most recent run for a schedule.
	GetLastRunForSchedule(ctx context.Context, scheduleID int64) (*BackupRun, error)

	// DeleteOldRuns deletes runs older than the specified age.
	// Returns the number of runs deleted.
	DeleteOldRuns(ctx context.Context, olderThan time.Time) (int64, error)

	// GetRunStats returns statistics about backup runs.
	GetRunStats(ctx context.Context) (*BackupRunStats, error)

	// GetRunningBackup returns the currently running backup, if any.
	// Used to prevent concurrent backups.
	GetRunningBackup(ctx context.Context) (*BackupRun, error)
}

// BackupRunStats contains statistics about backup runs.
type BackupRunStats struct {
	TotalRuns        int64     `json:"total_runs"`
	SuccessfulRuns   int64     `json:"successful_runs"`
	FailedRuns       int64     `json:"failed_runs"`
	TotalSizeBytes   int64     `json:"total_size_bytes"`
	LastSuccessfulAt *time.Time `json:"last_successful_at"`
	LastFailedAt     *time.Time `json:"last_failed_at"`
}
