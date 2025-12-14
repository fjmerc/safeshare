package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/fjmerc/safeshare/internal/repository"
)

// BackupSchedulerRepository implements repository.BackupSchedulerRepository for PostgreSQL.
type BackupSchedulerRepository struct {
	pool *Pool
}

// NewBackupSchedulerRepository creates a new PostgreSQL backup scheduler repository.
func NewBackupSchedulerRepository(pool *Pool) *BackupSchedulerRepository {
	return &BackupSchedulerRepository{pool: pool}
}

// Maximum limits for defense in depth
const (
	pgMaxScheduleNameLength     = 255
	pgMaxCronExpressionLength   = 100
	pgMaxBackupModeLength       = 20
	pgMaxOutputPathLength       = 1024
	pgMaxErrorMessageLength     = 10000
	pgMaxRetentionDays          = 3650 // 10 years
	pgMaxListLimit              = 1000
)

// Valid backup modes for defense in depth
var pgValidBackupModes = map[string]bool{
	"full":     true,
	"database": true,
	"config":   true,
}

// Valid trigger types for defense in depth
var pgValidTriggerTypes = map[repository.BackupTriggerType]bool{
	repository.BackupTriggerManual:    true,
	repository.BackupTriggerScheduled: true,
	repository.BackupTriggerAPI:       true,
}

// Valid run statuses for defense in depth
var pgValidRunStatuses = map[repository.BackupRunStatus]bool{
	repository.BackupRunStatusPending:   true,
	repository.BackupRunStatusRunning:   true,
	repository.BackupRunStatusCompleted: true,
	repository.BackupRunStatusFailed:    true,
}

// validateScheduleInput validates schedule fields before database operations.
func validateScheduleInput(name, schedule, mode string, retentionDays int) error {
	if len(name) == 0 {
		return errors.New("schedule name cannot be empty")
	}
	if len(name) > pgMaxScheduleNameLength {
		return fmt.Errorf("schedule name too long (max %d characters)", pgMaxScheduleNameLength)
	}
	if len(schedule) == 0 {
		return errors.New("cron expression cannot be empty")
	}
	if len(schedule) > pgMaxCronExpressionLength {
		return fmt.Errorf("cron expression too long (max %d characters)", pgMaxCronExpressionLength)
	}
	if !pgValidBackupModes[mode] {
		return fmt.Errorf("invalid backup mode: %s", mode)
	}
	if retentionDays < 0 || retentionDays > pgMaxRetentionDays {
		return fmt.Errorf("retention days must be between 0 and %d", pgMaxRetentionDays)
	}
	return nil
}

// === Schedule Management ===

// CreateSchedule creates a new backup schedule.
func (r *BackupSchedulerRepository) CreateSchedule(ctx context.Context, schedule *repository.BackupSchedule) error {
	if schedule == nil {
		return errors.New("schedule cannot be nil")
	}
	if err := validateScheduleInput(schedule.Name, schedule.Schedule, schedule.Mode, schedule.RetentionDays); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	now := time.Now().UTC()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO backup_schedules (name, enabled, schedule, mode, retention_days, next_run_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, schedule.Name, schedule.Enabled, schedule.Schedule, schedule.Mode, schedule.RetentionDays, schedule.NextRunAt, now, now).Scan(&schedule.ID)
	if err != nil {
		return fmt.Errorf("failed to create schedule: %w", err)
	}

	schedule.CreatedAt = now
	schedule.UpdatedAt = now
	return nil
}

// GetSchedule retrieves a schedule by ID.
func (r *BackupSchedulerRepository) GetSchedule(ctx context.Context, id int64) (*repository.BackupSchedule, error) {
	if id <= 0 {
		return nil, repository.ErrNotFound
	}

	var schedule repository.BackupSchedule
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, enabled, schedule, mode, retention_days, last_run_at, next_run_at, created_at, updated_at
		FROM backup_schedules WHERE id = $1
	`, id).Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &schedule.Schedule, &schedule.Mode, &schedule.RetentionDays, &schedule.LastRunAt, &schedule.NextRunAt, &schedule.CreatedAt, &schedule.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get schedule: %w", err)
	}

	return &schedule, nil
}

// GetScheduleByName retrieves a schedule by name.
func (r *BackupSchedulerRepository) GetScheduleByName(ctx context.Context, name string) (*repository.BackupSchedule, error) {
	if len(name) == 0 || len(name) > pgMaxScheduleNameLength {
		return nil, repository.ErrNotFound
	}

	var schedule repository.BackupSchedule
	err := r.pool.QueryRow(ctx, `
		SELECT id, name, enabled, schedule, mode, retention_days, last_run_at, next_run_at, created_at, updated_at
		FROM backup_schedules WHERE name = $1
	`, name).Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &schedule.Schedule, &schedule.Mode, &schedule.RetentionDays, &schedule.LastRunAt, &schedule.NextRunAt, &schedule.CreatedAt, &schedule.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get schedule by name: %w", err)
	}

	return &schedule, nil
}

// UpdateSchedule updates an existing schedule.
func (r *BackupSchedulerRepository) UpdateSchedule(ctx context.Context, schedule *repository.BackupSchedule) error {
	if schedule == nil || schedule.ID <= 0 {
		return repository.ErrNotFound
	}
	if err := validateScheduleInput(schedule.Name, schedule.Schedule, schedule.Mode, schedule.RetentionDays); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	now := time.Now().UTC()
	result, err := r.pool.Exec(ctx, `
		UPDATE backup_schedules SET name = $1, enabled = $2, schedule = $3, mode = $4, retention_days = $5, next_run_at = $6, updated_at = $7
		WHERE id = $8
	`, schedule.Name, schedule.Enabled, schedule.Schedule, schedule.Mode, schedule.RetentionDays, schedule.NextRunAt, now, schedule.ID)
	if err != nil {
		return fmt.Errorf("failed to update schedule: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	schedule.UpdatedAt = now
	return nil
}

// DeleteSchedule deletes a schedule by ID.
func (r *BackupSchedulerRepository) DeleteSchedule(ctx context.Context, id int64) error {
	if id <= 0 {
		return repository.ErrNotFound
	}

	result, err := r.pool.Exec(ctx, `DELETE FROM backup_schedules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("failed to delete schedule: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// ListSchedules returns all schedules.
func (r *BackupSchedulerRepository) ListSchedules(ctx context.Context) ([]repository.BackupSchedule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, enabled, schedule, mode, retention_days, last_run_at, next_run_at, created_at, updated_at
		FROM backup_schedules ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list schedules: %w", err)
	}
	defer rows.Close()

	var schedules []repository.BackupSchedule
	for rows.Next() {
		var schedule repository.BackupSchedule
		if err := rows.Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &schedule.Schedule, &schedule.Mode, &schedule.RetentionDays, &schedule.LastRunAt, &schedule.NextRunAt, &schedule.CreatedAt, &schedule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan schedule: %w", err)
		}
		schedules = append(schedules, schedule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating schedules: %w", err)
	}

	return schedules, nil
}

// GetDueSchedules returns enabled schedules that are due for execution.
func (r *BackupSchedulerRepository) GetDueSchedules(ctx context.Context, now time.Time) ([]repository.BackupSchedule, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, enabled, schedule, mode, retention_days, last_run_at, next_run_at, created_at, updated_at
		FROM backup_schedules 
		WHERE enabled = TRUE AND next_run_at IS NOT NULL AND next_run_at <= $1
		ORDER BY next_run_at
	`, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("failed to get due schedules: %w", err)
	}
	defer rows.Close()

	var schedules []repository.BackupSchedule
	for rows.Next() {
		var schedule repository.BackupSchedule
		if err := rows.Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &schedule.Schedule, &schedule.Mode, &schedule.RetentionDays, &schedule.LastRunAt, &schedule.NextRunAt, &schedule.CreatedAt, &schedule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan schedule: %w", err)
		}
		schedules = append(schedules, schedule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating due schedules: %w", err)
	}

	return schedules, nil
}

// UpdateScheduleLastRun updates the last_run_at and next_run_at fields.
func (r *BackupSchedulerRepository) UpdateScheduleLastRun(ctx context.Context, id int64, lastRunAt time.Time, nextRunAt time.Time) error {
	if id <= 0 {
		return repository.ErrNotFound
	}

	now := time.Now().UTC()
	result, err := r.pool.Exec(ctx, `
		UPDATE backup_schedules SET last_run_at = $1, next_run_at = $2, updated_at = $3
		WHERE id = $4
	`, lastRunAt.UTC(), nextRunAt.UTC(), now, id)
	if err != nil {
		return fmt.Errorf("failed to update schedule last run: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// === Backup Run Management ===

// CreateRun creates a new backup run record.
func (r *BackupSchedulerRepository) CreateRun(ctx context.Context, run *repository.BackupRun) error {
	if run == nil {
		return errors.New("run cannot be nil")
	}
	if !pgValidBackupModes[run.Mode] {
		return fmt.Errorf("invalid backup mode: %s", run.Mode)
	}
	if !pgValidTriggerTypes[run.TriggerType] {
		return fmt.Errorf("invalid trigger type: %s", run.TriggerType)
	}

	now := time.Now().UTC()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO backup_runs (schedule_id, trigger_type, status, mode, started_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`, run.ScheduleID, string(run.TriggerType), string(repository.BackupRunStatusPending), run.Mode, now).Scan(&run.ID)
	if err != nil {
		return fmt.Errorf("failed to create run: %w", err)
	}

	run.Status = repository.BackupRunStatusPending
	run.StartedAt = now
	return nil
}

// GetRun retrieves a run by ID.
func (r *BackupSchedulerRepository) GetRun(ctx context.Context, id int64) (*repository.BackupRun, error) {
	if id <= 0 {
		return nil, repository.ErrNotFound
	}

	var run repository.BackupRun
	var triggerType, status string
	var outputPath, errorMessage *string

	err := r.pool.QueryRow(ctx, `
		SELECT id, schedule_id, trigger_type, status, mode, output_path, size_bytes, files_backed_up, error_message, started_at, completed_at, duration_ms
		FROM backup_runs WHERE id = $1
	`, id).Scan(&run.ID, &run.ScheduleID, &triggerType, &status, &run.Mode, &outputPath, &run.SizeBytes, &run.FilesBackedUp, &errorMessage, &run.StartedAt, &run.CompletedAt, &run.DurationMs)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get run: %w", err)
	}

	run.TriggerType = repository.BackupTriggerType(triggerType)
	run.Status = repository.BackupRunStatus(status)
	if outputPath != nil {
		run.OutputPath = *outputPath
	}
	if errorMessage != nil {
		run.ErrorMessage = *errorMessage
	}

	return &run, nil
}

// UpdateRun updates an existing run.
func (r *BackupSchedulerRepository) UpdateRun(ctx context.Context, run *repository.BackupRun) error {
	if run == nil || run.ID <= 0 {
		return repository.ErrNotFound
	}
	if !pgValidRunStatuses[run.Status] {
		return fmt.Errorf("invalid run status: %s", run.Status)
	}
	if len(run.OutputPath) > pgMaxOutputPathLength {
		return fmt.Errorf("output path too long (max %d characters)", pgMaxOutputPathLength)
	}
	if len(run.ErrorMessage) > pgMaxErrorMessageLength {
		run.ErrorMessage = run.ErrorMessage[:pgMaxErrorMessageLength]
	}

	result, err := r.pool.Exec(ctx, `
		UPDATE backup_runs SET status = $1, output_path = $2, size_bytes = $3, files_backed_up = $4, error_message = $5, completed_at = $6, duration_ms = $7
		WHERE id = $8
	`, string(run.Status), run.OutputPath, run.SizeBytes, run.FilesBackedUp, run.ErrorMessage, run.CompletedAt, run.DurationMs, run.ID)
	if err != nil {
		return fmt.Errorf("failed to update run: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// CompleteRun marks a run as completed or failed.
func (r *BackupSchedulerRepository) CompleteRun(ctx context.Context, id int64, status repository.BackupRunStatus, outputPath string, sizeBytes int64, filesBackedUp int, errorMessage string) error {
	if id <= 0 {
		return repository.ErrNotFound
	}
	if !pgValidRunStatuses[status] {
		return fmt.Errorf("invalid run status: %s", status)
	}
	if len(outputPath) > pgMaxOutputPathLength {
		return fmt.Errorf("output path too long (max %d characters)", pgMaxOutputPathLength)
	}
	if len(errorMessage) > pgMaxErrorMessageLength {
		errorMessage = errorMessage[:pgMaxErrorMessageLength]
	}

	now := time.Now().UTC()

	// Get started_at to calculate duration
	var startedAt time.Time
	err := r.pool.QueryRow(ctx, `SELECT started_at FROM backup_runs WHERE id = $1`, id).Scan(&startedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("failed to get run started_at: %w", err)
	}

	durationMs := int(now.Sub(startedAt).Milliseconds())

	result, err := r.pool.Exec(ctx, `
		UPDATE backup_runs SET status = $1, output_path = $2, size_bytes = $3, files_backed_up = $4, error_message = $5, completed_at = $6, duration_ms = $7
		WHERE id = $8
	`, string(status), outputPath, sizeBytes, filesBackedUp, errorMessage, now, durationMs, id)
	if err != nil {
		return fmt.Errorf("failed to complete run: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// ListRuns returns runs matching the filter criteria.
func (r *BackupSchedulerRepository) ListRuns(ctx context.Context, filter repository.BackupRunFilter) ([]repository.BackupRun, error) {
	// Apply limits
	limit := filter.Limit
	if limit <= 0 || limit > pgMaxListLimit {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Build query dynamically
	query := `SELECT id, schedule_id, trigger_type, status, mode, output_path, size_bytes, files_backed_up, error_message, started_at, completed_at, duration_ms FROM backup_runs WHERE 1=1`
	args := make([]interface{}, 0)
	paramCount := 0

	if filter.ScheduleID != nil {
		paramCount++
		query += fmt.Sprintf(` AND schedule_id = $%d`, paramCount)
		args = append(args, *filter.ScheduleID)
	}
	if filter.Status != nil {
		paramCount++
		query += fmt.Sprintf(` AND status = $%d`, paramCount)
		args = append(args, string(*filter.Status))
	}
	if filter.TriggerType != nil {
		paramCount++
		query += fmt.Sprintf(` AND trigger_type = $%d`, paramCount)
		args = append(args, string(*filter.TriggerType))
	}

	paramCount++
	query += fmt.Sprintf(` ORDER BY started_at DESC LIMIT $%d`, paramCount)
	args = append(args, limit)

	paramCount++
	query += fmt.Sprintf(` OFFSET $%d`, paramCount)
	args = append(args, offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list runs: %w", err)
	}
	defer rows.Close()

	var runs []repository.BackupRun
	for rows.Next() {
		var run repository.BackupRun
		var triggerType, status string
		var outputPath, errorMessage *string

		if err := rows.Scan(&run.ID, &run.ScheduleID, &triggerType, &status, &run.Mode, &outputPath, &run.SizeBytes, &run.FilesBackedUp, &errorMessage, &run.StartedAt, &run.CompletedAt, &run.DurationMs); err != nil {
			return nil, fmt.Errorf("failed to scan run: %w", err)
		}

		run.TriggerType = repository.BackupTriggerType(triggerType)
		run.Status = repository.BackupRunStatus(status)
		if outputPath != nil {
			run.OutputPath = *outputPath
		}
		if errorMessage != nil {
			run.ErrorMessage = *errorMessage
		}

		runs = append(runs, run)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating runs: %w", err)
	}

	return runs, nil
}

// GetLastRunForSchedule returns the most recent run for a schedule.
func (r *BackupSchedulerRepository) GetLastRunForSchedule(ctx context.Context, scheduleID int64) (*repository.BackupRun, error) {
	if scheduleID <= 0 {
		return nil, repository.ErrNotFound
	}

	var run repository.BackupRun
	var triggerType, status string
	var outputPath, errorMessage *string

	err := r.pool.QueryRow(ctx, `
		SELECT id, schedule_id, trigger_type, status, mode, output_path, size_bytes, files_backed_up, error_message, started_at, completed_at, duration_ms
		FROM backup_runs WHERE schedule_id = $1
		ORDER BY started_at DESC LIMIT 1
	`, scheduleID).Scan(&run.ID, &run.ScheduleID, &triggerType, &status, &run.Mode, &outputPath, &run.SizeBytes, &run.FilesBackedUp, &errorMessage, &run.StartedAt, &run.CompletedAt, &run.DurationMs)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get last run for schedule: %w", err)
	}

	run.TriggerType = repository.BackupTriggerType(triggerType)
	run.Status = repository.BackupRunStatus(status)
	if outputPath != nil {
		run.OutputPath = *outputPath
	}
	if errorMessage != nil {
		run.ErrorMessage = *errorMessage
	}

	return &run, nil
}

// DeleteOldRuns deletes runs older than the specified age.
func (r *BackupSchedulerRepository) DeleteOldRuns(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := r.pool.Exec(ctx, `
		DELETE FROM backup_runs WHERE completed_at IS NOT NULL AND completed_at < $1
	`, olderThan.UTC())
	if err != nil {
		return 0, fmt.Errorf("failed to delete old runs: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetRunStats returns statistics about backup runs.
func (r *BackupSchedulerRepository) GetRunStats(ctx context.Context) (*repository.BackupRunStats, error) {
	var stats repository.BackupRunStats

	err := r.pool.QueryRow(ctx, `
		SELECT 
			COUNT(*) as total_runs,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as successful_runs,
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed_runs,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN size_bytes ELSE 0 END), 0) as total_size_bytes,
			(SELECT completed_at FROM backup_runs WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1) as last_successful_at,
			(SELECT completed_at FROM backup_runs WHERE status = 'failed' ORDER BY completed_at DESC LIMIT 1) as last_failed_at
		FROM backup_runs
	`).Scan(&stats.TotalRuns, &stats.SuccessfulRuns, &stats.FailedRuns, &stats.TotalSizeBytes, &stats.LastSuccessfulAt, &stats.LastFailedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to get run stats: %w", err)
	}

	return &stats, nil
}

// GetRunningBackup returns the currently running backup, if any.
func (r *BackupSchedulerRepository) GetRunningBackup(ctx context.Context) (*repository.BackupRun, error) {
	var run repository.BackupRun
	var triggerType, status string
	var outputPath, errorMessage *string

	err := r.pool.QueryRow(ctx, `
		SELECT id, schedule_id, trigger_type, status, mode, output_path, size_bytes, files_backed_up, error_message, started_at, completed_at, duration_ms
		FROM backup_runs WHERE status = 'running'
		ORDER BY started_at DESC LIMIT 1
	`).Scan(&run.ID, &run.ScheduleID, &triggerType, &status, &run.Mode, &outputPath, &run.SizeBytes, &run.FilesBackedUp, &errorMessage, &run.StartedAt, &run.CompletedAt, &run.DurationMs)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // No running backup
		}
		return nil, fmt.Errorf("failed to get running backup: %w", err)
	}

	run.TriggerType = repository.BackupTriggerType(triggerType)
	run.Status = repository.BackupRunStatus(status)
	if outputPath != nil {
		run.OutputPath = *outputPath
	}
	if errorMessage != nil {
		run.ErrorMessage = *errorMessage
	}

	return &run, nil
}
