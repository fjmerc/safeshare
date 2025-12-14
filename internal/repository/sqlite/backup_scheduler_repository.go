package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// BackupSchedulerRepository implements repository.BackupSchedulerRepository for SQLite.
type BackupSchedulerRepository struct {
	db *sql.DB
}

// NewBackupSchedulerRepository creates a new SQLite backup scheduler repository.
func NewBackupSchedulerRepository(db *sql.DB) *BackupSchedulerRepository {
	return &BackupSchedulerRepository{db: db}
}

// Maximum limits for defense in depth
const (
	maxScheduleNameLength     = 255
	maxCronExpressionLength   = 100
	maxBackupModeLength       = 20
	maxOutputPathLength       = 1024
	maxErrorMessageLength     = 10000
	maxRetentionDays          = 3650 // 10 years
	maxListLimit              = 1000
)

// Valid backup modes for defense in depth
var validBackupModes = map[string]bool{
	"full":     true,
	"database": true,
	"config":   true,
}

// Valid trigger types for defense in depth
var validTriggerTypes = map[repository.BackupTriggerType]bool{
	repository.BackupTriggerManual:    true,
	repository.BackupTriggerScheduled: true,
	repository.BackupTriggerAPI:       true,
}

// Valid run statuses for defense in depth
var validRunStatuses = map[repository.BackupRunStatus]bool{
	repository.BackupRunStatusPending:   true,
	repository.BackupRunStatusRunning:   true,
	repository.BackupRunStatusCompleted: true,
	repository.BackupRunStatusFailed:    true,
}

// validateSchedule validates schedule fields before database operations.
func validateSchedule(schedule *BackupScheduleInput) error {
	if schedule == nil {
		return errors.New("schedule cannot be nil")
	}
	if len(schedule.Name) == 0 {
		return errors.New("schedule name cannot be empty")
	}
	if len(schedule.Name) > maxScheduleNameLength {
		return fmt.Errorf("schedule name too long (max %d characters)", maxScheduleNameLength)
	}
	if len(schedule.Schedule) == 0 {
		return errors.New("cron expression cannot be empty")
	}
	if len(schedule.Schedule) > maxCronExpressionLength {
		return fmt.Errorf("cron expression too long (max %d characters)", maxCronExpressionLength)
	}
	if !validBackupModes[schedule.Mode] {
		return fmt.Errorf("invalid backup mode: %s", schedule.Mode)
	}
	if schedule.RetentionDays < 0 || schedule.RetentionDays > maxRetentionDays {
		return fmt.Errorf("retention days must be between 0 and %d", maxRetentionDays)
	}
	return nil
}

// BackupScheduleInput is used for validation (subset of BackupSchedule).
type BackupScheduleInput struct {
	Name          string
	Schedule      string
	Mode          string
	RetentionDays int
}

// === Schedule Management ===

// CreateSchedule creates a new backup schedule.
func (r *BackupSchedulerRepository) CreateSchedule(ctx context.Context, schedule *repository.BackupSchedule) error {
	input := &BackupScheduleInput{
		Name:          schedule.Name,
		Schedule:      schedule.Schedule,
		Mode:          schedule.Mode,
		RetentionDays: schedule.RetentionDays,
	}
	if err := validateSchedule(input); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	now := time.Now().UTC()
	var nextRunAt *string
	if schedule.NextRunAt != nil {
		t := schedule.NextRunAt.UTC().Format(time.RFC3339)
		nextRunAt = &t
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO backup_schedules (name, enabled, schedule, mode, retention_days, next_run_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, schedule.Name, schedule.Enabled, schedule.Schedule, schedule.Mode, schedule.RetentionDays, nextRunAt, now.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to create schedule: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get schedule ID: %w", err)
	}
	schedule.ID = id
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
	var lastRunAt, nextRunAt, createdAt, updatedAt sql.NullString

	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, enabled, schedule, mode, retention_days, last_run_at, next_run_at, created_at, updated_at
		FROM backup_schedules WHERE id = ?
	`, id).Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &schedule.Schedule, &schedule.Mode, &schedule.RetentionDays, &lastRunAt, &nextRunAt, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get schedule: %w", err)
	}

	if lastRunAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastRunAt.String)
		schedule.LastRunAt = &t
	}
	if nextRunAt.Valid {
		t, _ := time.Parse(time.RFC3339, nextRunAt.String)
		schedule.NextRunAt = &t
	}
	if createdAt.Valid {
		schedule.CreatedAt, _ = time.Parse(time.RFC3339, createdAt.String)
	}
	if updatedAt.Valid {
		schedule.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt.String)
	}

	return &schedule, nil
}

// GetScheduleByName retrieves a schedule by name.
func (r *BackupSchedulerRepository) GetScheduleByName(ctx context.Context, name string) (*repository.BackupSchedule, error) {
	if len(name) == 0 || len(name) > maxScheduleNameLength {
		return nil, repository.ErrNotFound
	}

	var schedule repository.BackupSchedule
	var lastRunAt, nextRunAt, createdAt, updatedAt sql.NullString

	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, enabled, schedule, mode, retention_days, last_run_at, next_run_at, created_at, updated_at
		FROM backup_schedules WHERE name = ?
	`, name).Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &schedule.Schedule, &schedule.Mode, &schedule.RetentionDays, &lastRunAt, &nextRunAt, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get schedule by name: %w", err)
	}

	if lastRunAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastRunAt.String)
		schedule.LastRunAt = &t
	}
	if nextRunAt.Valid {
		t, _ := time.Parse(time.RFC3339, nextRunAt.String)
		schedule.NextRunAt = &t
	}
	if createdAt.Valid {
		schedule.CreatedAt, _ = time.Parse(time.RFC3339, createdAt.String)
	}
	if updatedAt.Valid {
		schedule.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt.String)
	}

	return &schedule, nil
}

// UpdateSchedule updates an existing schedule.
func (r *BackupSchedulerRepository) UpdateSchedule(ctx context.Context, schedule *repository.BackupSchedule) error {
	if schedule.ID <= 0 {
		return repository.ErrNotFound
	}

	input := &BackupScheduleInput{
		Name:          schedule.Name,
		Schedule:      schedule.Schedule,
		Mode:          schedule.Mode,
		RetentionDays: schedule.RetentionDays,
	}
	if err := validateSchedule(input); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	now := time.Now().UTC()
	var nextRunAt *string
	if schedule.NextRunAt != nil {
		t := schedule.NextRunAt.UTC().Format(time.RFC3339)
		nextRunAt = &t
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE backup_schedules SET name = ?, enabled = ?, schedule = ?, mode = ?, retention_days = ?, next_run_at = ?, updated_at = ?
		WHERE id = ?
	`, schedule.Name, schedule.Enabled, schedule.Schedule, schedule.Mode, schedule.RetentionDays, nextRunAt, now.Format(time.RFC3339), schedule.ID)
	if err != nil {
		return fmt.Errorf("failed to update schedule: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
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

	result, err := r.db.ExecContext(ctx, `DELETE FROM backup_schedules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete schedule: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// ListSchedules returns all schedules.
func (r *BackupSchedulerRepository) ListSchedules(ctx context.Context) ([]repository.BackupSchedule, error) {
	rows, err := r.db.QueryContext(ctx, `
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
		var lastRunAt, nextRunAt, createdAt, updatedAt sql.NullString

		if err := rows.Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &schedule.Schedule, &schedule.Mode, &schedule.RetentionDays, &lastRunAt, &nextRunAt, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan schedule: %w", err)
		}

		if lastRunAt.Valid {
			t, _ := time.Parse(time.RFC3339, lastRunAt.String)
			schedule.LastRunAt = &t
		}
		if nextRunAt.Valid {
			t, _ := time.Parse(time.RFC3339, nextRunAt.String)
			schedule.NextRunAt = &t
		}
		if createdAt.Valid {
			schedule.CreatedAt, _ = time.Parse(time.RFC3339, createdAt.String)
		}
		if updatedAt.Valid {
			schedule.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt.String)
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
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, enabled, schedule, mode, retention_days, last_run_at, next_run_at, created_at, updated_at
		FROM backup_schedules 
		WHERE enabled = 1 AND next_run_at IS NOT NULL AND next_run_at <= ?
		ORDER BY next_run_at
	`, now.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("failed to get due schedules: %w", err)
	}
	defer rows.Close()

	var schedules []repository.BackupSchedule
	for rows.Next() {
		var schedule repository.BackupSchedule
		var lastRunAt, nextRunAt, createdAt, updatedAt sql.NullString

		if err := rows.Scan(&schedule.ID, &schedule.Name, &schedule.Enabled, &schedule.Schedule, &schedule.Mode, &schedule.RetentionDays, &lastRunAt, &nextRunAt, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan schedule: %w", err)
		}

		if lastRunAt.Valid {
			t, _ := time.Parse(time.RFC3339, lastRunAt.String)
			schedule.LastRunAt = &t
		}
		if nextRunAt.Valid {
			t, _ := time.Parse(time.RFC3339, nextRunAt.String)
			schedule.NextRunAt = &t
		}
		if createdAt.Valid {
			schedule.CreatedAt, _ = time.Parse(time.RFC3339, createdAt.String)
		}
		if updatedAt.Valid {
			schedule.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt.String)
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
	result, err := r.db.ExecContext(ctx, `
		UPDATE backup_schedules SET last_run_at = ?, next_run_at = ?, updated_at = ?
		WHERE id = ?
	`, lastRunAt.UTC().Format(time.RFC3339), nextRunAt.UTC().Format(time.RFC3339), now.Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("failed to update schedule last run: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
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
	if !validBackupModes[run.Mode] {
		return fmt.Errorf("invalid backup mode: %s", run.Mode)
	}
	if !validTriggerTypes[run.TriggerType] {
		return fmt.Errorf("invalid trigger type: %s", run.TriggerType)
	}

	now := time.Now().UTC()
	var scheduleID *int64
	if run.ScheduleID != nil {
		scheduleID = run.ScheduleID
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO backup_runs (schedule_id, trigger_type, status, mode, started_at)
		VALUES (?, ?, ?, ?, ?)
	`, scheduleID, string(run.TriggerType), string(repository.BackupRunStatusPending), run.Mode, now.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to create run: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get run ID: %w", err)
	}

	run.ID = id
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
	var scheduleID sql.NullInt64
	var triggerType, status string
	var outputPath, errorMessage sql.NullString
	var startedAt, completedAt sql.NullString

	err := r.db.QueryRowContext(ctx, `
		SELECT id, schedule_id, trigger_type, status, mode, output_path, size_bytes, files_backed_up, error_message, started_at, completed_at, duration_ms
		FROM backup_runs WHERE id = ?
	`, id).Scan(&run.ID, &scheduleID, &triggerType, &status, &run.Mode, &outputPath, &run.SizeBytes, &run.FilesBackedUp, &errorMessage, &startedAt, &completedAt, &run.DurationMs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get run: %w", err)
	}

	if scheduleID.Valid {
		run.ScheduleID = &scheduleID.Int64
	}
	run.TriggerType = repository.BackupTriggerType(triggerType)
	run.Status = repository.BackupRunStatus(status)
	if outputPath.Valid {
		run.OutputPath = outputPath.String
	}
	if errorMessage.Valid {
		run.ErrorMessage = errorMessage.String
	}
	if startedAt.Valid {
		run.StartedAt, _ = time.Parse(time.RFC3339, startedAt.String)
	}
	if completedAt.Valid {
		t, _ := time.Parse(time.RFC3339, completedAt.String)
		run.CompletedAt = &t
	}

	return &run, nil
}

// UpdateRun updates an existing run.
func (r *BackupSchedulerRepository) UpdateRun(ctx context.Context, run *repository.BackupRun) error {
	if run == nil || run.ID <= 0 {
		return repository.ErrNotFound
	}
	if !validRunStatuses[run.Status] {
		return fmt.Errorf("invalid run status: %s", run.Status)
	}
	if len(run.OutputPath) > maxOutputPathLength {
		return fmt.Errorf("output path too long (max %d characters)", maxOutputPathLength)
	}
	if len(run.ErrorMessage) > maxErrorMessageLength {
		// Truncate error message instead of rejecting
		run.ErrorMessage = run.ErrorMessage[:maxErrorMessageLength]
	}

	var completedAt *string
	if run.CompletedAt != nil {
		t := run.CompletedAt.UTC().Format(time.RFC3339)
		completedAt = &t
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE backup_runs SET status = ?, output_path = ?, size_bytes = ?, files_backed_up = ?, error_message = ?, completed_at = ?, duration_ms = ?
		WHERE id = ?
	`, string(run.Status), run.OutputPath, run.SizeBytes, run.FilesBackedUp, run.ErrorMessage, completedAt, run.DurationMs, run.ID)
	if err != nil {
		return fmt.Errorf("failed to update run: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// CompleteRun marks a run as completed or failed.
func (r *BackupSchedulerRepository) CompleteRun(ctx context.Context, id int64, status repository.BackupRunStatus, outputPath string, sizeBytes int64, filesBackedUp int, errorMessage string) error {
	if id <= 0 {
		return repository.ErrNotFound
	}
	if !validRunStatuses[status] {
		return fmt.Errorf("invalid run status: %s", status)
	}
	if len(outputPath) > maxOutputPathLength {
		return fmt.Errorf("output path too long (max %d characters)", maxOutputPathLength)
	}
	if len(errorMessage) > maxErrorMessageLength {
		errorMessage = errorMessage[:maxErrorMessageLength]
	}

	now := time.Now().UTC()

	// Get started_at to calculate duration
	var startedAtStr sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT started_at FROM backup_runs WHERE id = ?`, id).Scan(&startedAtStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("failed to get run started_at: %w", err)
	}

	var durationMs int
	if startedAtStr.Valid {
		startedAt, _ := time.Parse(time.RFC3339, startedAtStr.String)
		durationMs = int(now.Sub(startedAt).Milliseconds())
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE backup_runs SET status = ?, output_path = ?, size_bytes = ?, files_backed_up = ?, error_message = ?, completed_at = ?, duration_ms = ?
		WHERE id = ?
	`, string(status), outputPath, sizeBytes, filesBackedUp, errorMessage, now.Format(time.RFC3339), durationMs, id)
	if err != nil {
		return fmt.Errorf("failed to complete run: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// ListRuns returns runs matching the filter criteria.
func (r *BackupSchedulerRepository) ListRuns(ctx context.Context, filter repository.BackupRunFilter) ([]repository.BackupRun, error) {
	// Apply limits
	limit := filter.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Build query dynamically
	query := `SELECT id, schedule_id, trigger_type, status, mode, output_path, size_bytes, files_backed_up, error_message, started_at, completed_at, duration_ms FROM backup_runs WHERE 1=1`
	args := make([]interface{}, 0)

	if filter.ScheduleID != nil {
		query += ` AND schedule_id = ?`
		args = append(args, *filter.ScheduleID)
	}
	if filter.Status != nil {
		query += ` AND status = ?`
		args = append(args, string(*filter.Status))
	}
	if filter.TriggerType != nil {
		query += ` AND trigger_type = ?`
		args = append(args, string(*filter.TriggerType))
	}

	query += ` ORDER BY started_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list runs: %w", err)
	}
	defer rows.Close()

	var runs []repository.BackupRun
	for rows.Next() {
		var run repository.BackupRun
		var scheduleID sql.NullInt64
		var triggerType, status string
		var outputPath, errorMessage sql.NullString
		var startedAt, completedAt sql.NullString

		if err := rows.Scan(&run.ID, &scheduleID, &triggerType, &status, &run.Mode, &outputPath, &run.SizeBytes, &run.FilesBackedUp, &errorMessage, &startedAt, &completedAt, &run.DurationMs); err != nil {
			return nil, fmt.Errorf("failed to scan run: %w", err)
		}

		if scheduleID.Valid {
			run.ScheduleID = &scheduleID.Int64
		}
		run.TriggerType = repository.BackupTriggerType(triggerType)
		run.Status = repository.BackupRunStatus(status)
		if outputPath.Valid {
			run.OutputPath = outputPath.String
		}
		if errorMessage.Valid {
			run.ErrorMessage = errorMessage.String
		}
		if startedAt.Valid {
			run.StartedAt, _ = time.Parse(time.RFC3339, startedAt.String)
		}
		if completedAt.Valid {
			t, _ := time.Parse(time.RFC3339, completedAt.String)
			run.CompletedAt = &t
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
	var schedID sql.NullInt64
	var triggerType, status string
	var outputPath, errorMessage sql.NullString
	var startedAt, completedAt sql.NullString

	err := r.db.QueryRowContext(ctx, `
		SELECT id, schedule_id, trigger_type, status, mode, output_path, size_bytes, files_backed_up, error_message, started_at, completed_at, duration_ms
		FROM backup_runs WHERE schedule_id = ?
		ORDER BY started_at DESC LIMIT 1
	`, scheduleID).Scan(&run.ID, &schedID, &triggerType, &status, &run.Mode, &outputPath, &run.SizeBytes, &run.FilesBackedUp, &errorMessage, &startedAt, &completedAt, &run.DurationMs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get last run for schedule: %w", err)
	}

	if schedID.Valid {
		run.ScheduleID = &schedID.Int64
	}
	run.TriggerType = repository.BackupTriggerType(triggerType)
	run.Status = repository.BackupRunStatus(status)
	if outputPath.Valid {
		run.OutputPath = outputPath.String
	}
	if errorMessage.Valid {
		run.ErrorMessage = errorMessage.String
	}
	if startedAt.Valid {
		run.StartedAt, _ = time.Parse(time.RFC3339, startedAt.String)
	}
	if completedAt.Valid {
		t, _ := time.Parse(time.RFC3339, completedAt.String)
		run.CompletedAt = &t
	}

	return &run, nil
}

// DeleteOldRuns deletes runs older than the specified age.
func (r *BackupSchedulerRepository) DeleteOldRuns(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM backup_runs WHERE completed_at IS NOT NULL AND completed_at < ?
	`, olderThan.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("failed to delete old runs: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// GetRunStats returns statistics about backup runs.
func (r *BackupSchedulerRepository) GetRunStats(ctx context.Context) (*repository.BackupRunStats, error) {
	var stats repository.BackupRunStats
	var lastSuccessfulAt, lastFailedAt sql.NullString

	err := r.db.QueryRowContext(ctx, `
		SELECT 
			COUNT(*) as total_runs,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as successful_runs,
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed_runs,
			COALESCE(SUM(CASE WHEN status = 'completed' THEN size_bytes ELSE 0 END), 0) as total_size_bytes,
			(SELECT completed_at FROM backup_runs WHERE status = 'completed' ORDER BY completed_at DESC LIMIT 1) as last_successful_at,
			(SELECT completed_at FROM backup_runs WHERE status = 'failed' ORDER BY completed_at DESC LIMIT 1) as last_failed_at
		FROM backup_runs
	`).Scan(&stats.TotalRuns, &stats.SuccessfulRuns, &stats.FailedRuns, &stats.TotalSizeBytes, &lastSuccessfulAt, &lastFailedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to get run stats: %w", err)
	}

	if lastSuccessfulAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastSuccessfulAt.String)
		stats.LastSuccessfulAt = &t
	}
	if lastFailedAt.Valid {
		t, _ := time.Parse(time.RFC3339, lastFailedAt.String)
		stats.LastFailedAt = &t
	}

	return &stats, nil
}

// GetRunningBackup returns the currently running backup, if any.
func (r *BackupSchedulerRepository) GetRunningBackup(ctx context.Context) (*repository.BackupRun, error) {
	var run repository.BackupRun
	var scheduleID sql.NullInt64
	var triggerType, status string
	var outputPath, errorMessage sql.NullString
	var startedAt, completedAt sql.NullString

	err := r.db.QueryRowContext(ctx, `
		SELECT id, schedule_id, trigger_type, status, mode, output_path, size_bytes, files_backed_up, error_message, started_at, completed_at, duration_ms
		FROM backup_runs WHERE status = 'running'
		ORDER BY started_at DESC LIMIT 1
	`).Scan(&run.ID, &scheduleID, &triggerType, &status, &run.Mode, &outputPath, &run.SizeBytes, &run.FilesBackedUp, &errorMessage, &startedAt, &completedAt, &run.DurationMs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No running backup
		}
		return nil, fmt.Errorf("failed to get running backup: %w", err)
	}

	if scheduleID.Valid {
		run.ScheduleID = &scheduleID.Int64
	}
	run.TriggerType = repository.BackupTriggerType(triggerType)
	run.Status = repository.BackupRunStatus(status)
	if outputPath.Valid {
		run.OutputPath = outputPath.String
	}
	if errorMessage.Valid {
		run.ErrorMessage = errorMessage.String
	}
	if startedAt.Valid {
		run.StartedAt, _ = time.Parse(time.RFC3339, startedAt.String)
	}
	if completedAt.Valid {
		t, _ := time.Parse(time.RFC3339, completedAt.String)
		run.CompletedAt = &t
	}

	return &run, nil
}
