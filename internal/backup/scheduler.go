// Package backup provides functionality for creating and restoring SafeShare backups.
package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// cronFieldRegex validates individual cron expression fields.
var cronFieldRegex = regexp.MustCompile(`^(\*|[0-9]+)$`)

// backupDirNameRegex validates backup directory names (backup-YYYYMMDD-HHMMSS format).
var backupDirNameRegex = regexp.MustCompile(`^backup-\d{8}-\d{6}$`)

// ErrBackupAlreadyRunning indicates a backup is already in progress.
var ErrBackupAlreadyRunning = errors.New("another backup is already running")

// ErrInvalidCronExpression indicates an invalid cron expression.
var ErrInvalidCronExpression = errors.New("invalid cron expression")

// Scheduler manages automatic backup execution based on configured schedules.
type Scheduler struct {
	cfg         *config.Config
	repos       *repository.Repositories
	mu          sync.Mutex
	running     atomic.Bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	backupMu    sync.Mutex     // Protects backup execution to prevent concurrent backups
	backupWg    sync.WaitGroup // Tracks running backup goroutines for graceful shutdown

	// checkInterval determines how often the scheduler checks for due backups.
	checkInterval time.Duration
}

// NewScheduler creates a new backup scheduler.
func NewScheduler(cfg *config.Config, repos *repository.Repositories) *Scheduler {
	return &Scheduler{
		cfg:           cfg,
		repos:         repos,
		checkInterval: time.Minute, // Check every minute for due schedules
	}
}

// Start begins the scheduler's background goroutine.
// It periodically checks for due backup schedules and executes them.
// This method is non-blocking and returns immediately.
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running.Load() {
		return fmt.Errorf("scheduler already running")
	}

	// Clean up any orphaned backup runs from previous crashes
	s.cleanupOrphanedRuns(ctx)

	// Initialize schedules from config if auto-backup is enabled
	if s.cfg.AutoBackup != nil && s.cfg.AutoBackup.Enabled {
		if err := s.initializeDefaultSchedule(ctx); err != nil {
			slog.Warn("failed to initialize default backup schedule from config", "error", err)
		}
	}

	s.stopCh = make(chan struct{})
	s.running.Store(true)

	s.wg.Add(1)
	go s.run(ctx)

	slog.Info("backup scheduler started", "check_interval", s.checkInterval)
	return nil
}

// Stop gracefully stops the scheduler.
// It waits for any currently running backup to complete before returning.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running.Load() {
		s.mu.Unlock()
		return
	}
	s.running.Store(false)
	close(s.stopCh)
	s.mu.Unlock()

	// Wait for scheduler loop to finish
	s.wg.Wait()

	// Wait for any running backup goroutines to finish
	s.backupWg.Wait()

	slog.Info("backup scheduler stopped")
}

// cleanupOrphanedRuns marks any runs that were left in "running" status as failed.
// This handles the case where the scheduler crashed mid-backup.
func (s *Scheduler) cleanupOrphanedRuns(ctx context.Context) {
	runningBackup, err := s.repos.BackupScheduler.GetRunningBackup(ctx)
	if err != nil {
		slog.Error("failed to check for orphaned backup runs", "error", err)
		return
	}

	if runningBackup != nil {
		slog.Warn("found orphaned backup run from previous crash, marking as failed",
			"run_id", runningBackup.ID)
		err := s.repos.BackupScheduler.CompleteRun(
			ctx,
			runningBackup.ID,
			repository.BackupRunStatusFailed,
			"",
			0,
			0,
			"backup interrupted by scheduler restart",
		)
		if err != nil {
			slog.Error("failed to mark orphaned backup run as failed", "error", err, "run_id", runningBackup.ID)
		}
	}
}

// IsRunning returns whether the scheduler is currently running.
func (s *Scheduler) IsRunning() bool {
	return s.running.Load()
}

// ValidateCronExpression validates a cron expression.
// Supported format: minute hour day month weekday
// Examples: "0 2 * * *" (2 AM daily), "0 0 * * 0" (midnight Sunday)
func ValidateCronExpression(cronExpr string) error {
	fields := strings.Fields(cronExpr)
	if len(fields) != 5 {
		return fmt.Errorf("%w: expected 5 fields, got %d", ErrInvalidCronExpression, len(fields))
	}

	// Validate minute (0-59)
	if err := validateCronField(fields[0], 0, 59, "minute"); err != nil {
		return err
	}

	// Validate hour (0-23)
	if err := validateCronField(fields[1], 0, 23, "hour"); err != nil {
		return err
	}

	// Validate day of month (1-31)
	if err := validateCronField(fields[2], 1, 31, "day of month"); err != nil {
		return err
	}

	// Validate month (1-12)
	if err := validateCronField(fields[3], 1, 12, "month"); err != nil {
		return err
	}

	// Validate day of week (0-6, 0 = Sunday)
	if err := validateCronField(fields[4], 0, 6, "day of week"); err != nil {
		return err
	}

	return nil
}

// validateCronField validates a single cron field.
func validateCronField(field string, minVal, maxVal int, fieldName string) error {
	if field == "*" {
		return nil
	}

	if !cronFieldRegex.MatchString(field) {
		return fmt.Errorf("%w: invalid %s field '%s'", ErrInvalidCronExpression, fieldName, field)
	}

	val, err := strconv.Atoi(field)
	if err != nil {
		return fmt.Errorf("%w: %s must be a number or '*'", ErrInvalidCronExpression, fieldName)
	}

	if val < minVal || val > maxVal {
		return fmt.Errorf("%w: %s must be between %d and %d, got %d", ErrInvalidCronExpression, fieldName, minVal, maxVal, val)
	}

	return nil
}

// initializeDefaultSchedule creates or updates the default schedule from config.
func (s *Scheduler) initializeDefaultSchedule(ctx context.Context) error {
	if s.cfg.AutoBackup == nil {
		return nil
	}

	// Validate cron expression before using
	if err := ValidateCronExpression(s.cfg.AutoBackup.Schedule); err != nil {
		return fmt.Errorf("invalid cron expression in config: %w", err)
	}

	schedule, err := s.repos.BackupScheduler.GetScheduleByName(ctx, "default")
	if err != nil && err != repository.ErrNotFound {
		return fmt.Errorf("failed to get default schedule: %w", err)
	}

	// Calculate next run time based on current time and schedule
	nextRun := s.calculateNextRun(s.cfg.AutoBackup.Schedule, time.Now())

	if schedule == nil {
		// Create default schedule
		schedule = &repository.BackupSchedule{
			Name:          "default",
			Enabled:       s.cfg.AutoBackup.Enabled,
			Schedule:      s.cfg.AutoBackup.Schedule,
			Mode:          s.cfg.AutoBackup.Mode,
			RetentionDays: s.cfg.AutoBackup.RetentionDays,
			NextRunAt:     nextRun,
		}
		if err := s.repos.BackupScheduler.CreateSchedule(ctx, schedule); err != nil {
			return fmt.Errorf("failed to create default schedule: %w", err)
		}
		slog.Info("created default backup schedule from config",
			"schedule", schedule.Schedule,
			"mode", schedule.Mode,
			"retention_days", schedule.RetentionDays,
			"next_run", nextRun)
	} else {
		// Update default schedule from config
		schedule.Enabled = s.cfg.AutoBackup.Enabled
		schedule.Schedule = s.cfg.AutoBackup.Schedule
		schedule.Mode = s.cfg.AutoBackup.Mode
		schedule.RetentionDays = s.cfg.AutoBackup.RetentionDays
		if schedule.NextRunAt == nil {
			schedule.NextRunAt = nextRun
		}
		if err := s.repos.BackupScheduler.UpdateSchedule(ctx, schedule); err != nil {
			return fmt.Errorf("failed to update default schedule: %w", err)
		}
		slog.Info("updated default backup schedule from config",
			"schedule", schedule.Schedule,
			"mode", schedule.Mode,
			"enabled", schedule.Enabled)
	}

	return nil
}

// run is the main scheduler loop.
func (s *Scheduler) run(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkAndRunDueSchedules(ctx)
		}
	}
}

// checkAndRunDueSchedules checks for and executes any due backup schedules.
func (s *Scheduler) checkAndRunDueSchedules(ctx context.Context) {
	now := time.Now()

	// Get due schedules
	schedules, err := s.repos.BackupScheduler.GetDueSchedules(ctx, now)
	if err != nil {
		slog.Error("failed to get due schedules", "error", err)
		return
	}

	for _, schedule := range schedules {
		scheduleCopy := schedule // Create copy for goroutine
		s.executeScheduledBackup(ctx, &scheduleCopy)
	}
}

// executeScheduledBackup runs a backup for the given schedule.
// Uses mutex to prevent concurrent backup execution (fixes race condition).
func (s *Scheduler) executeScheduledBackup(ctx context.Context, schedule *repository.BackupSchedule) {
	// Acquire backup mutex to prevent race condition between check and execution
	s.backupMu.Lock()

	// Double-check if another backup is already running (under mutex protection)
	runningBackup, err := s.repos.BackupScheduler.GetRunningBackup(ctx)
	if err != nil {
		s.backupMu.Unlock()
		slog.Error("failed to check for running backup", "error", err)
		return
	}
	if runningBackup != nil {
		s.backupMu.Unlock()
		slog.Warn("skipping scheduled backup, another backup is running",
			"schedule", schedule.Name,
			"running_backup_id", runningBackup.ID)
		return
	}

	slog.Info("executing scheduled backup",
		"schedule_id", schedule.ID,
		"schedule_name", schedule.Name,
		"mode", schedule.Mode)

	// Create backup run record
	scheduleID := schedule.ID
	run := &repository.BackupRun{
		ScheduleID:  &scheduleID,
		TriggerType: repository.BackupTriggerScheduled,
		Mode:        schedule.Mode,
	}
	if err := s.repos.BackupScheduler.CreateRun(ctx, run); err != nil {
		s.backupMu.Unlock()
		slog.Error("failed to create backup run record", "error", err)
		return
	}

	// Update run status to running
	run.Status = repository.BackupRunStatusRunning
	if err := s.repos.BackupScheduler.UpdateRun(ctx, run); err != nil {
		s.backupMu.Unlock()
		slog.Error("failed to update backup run status", "error", err)
		return
	}

	// Release mutex - we've successfully claimed the backup slot
	s.backupMu.Unlock()

	// Execute the backup (blocking - scheduled backups run synchronously)
	result := s.performBackup(ctx, schedule.Mode)

	// Update schedule last run time and calculate next run
	nextRun := s.calculateNextRun(schedule.Schedule, time.Now())
	if err := s.repos.BackupScheduler.UpdateScheduleLastRun(ctx, schedule.ID, time.Now(), *nextRun); err != nil {
		slog.Error("failed to update schedule last run", "error", err, "schedule_id", schedule.ID)
	}

	// Complete the run record
	var status repository.BackupRunStatus
	var errorMessage string
	var outputPath string
	var sizeBytes int64
	var filesBackedUp int

	if result.Success {
		status = repository.BackupRunStatusCompleted
		outputPath = result.BackupPath
		if result.Manifest != nil {
			sizeBytes = result.Manifest.Stats.TotalSizeBytes
			filesBackedUp = result.Manifest.Stats.FilesBackedUp
		}
		slog.Info("scheduled backup completed successfully",
			"schedule_name", schedule.Name,
			"output_path", outputPath,
			"size_bytes", sizeBytes,
			"duration", result.DurationString)
	} else {
		status = repository.BackupRunStatusFailed
		// Sanitize error message to avoid exposing internal paths
		errorMessage = sanitizeErrorMessage(result.Error)
		slog.Error("scheduled backup failed",
			"schedule_name", schedule.Name,
			"error", result.Error, // Log full error internally
			"duration", result.DurationString)
	}

	if err := s.repos.BackupScheduler.CompleteRun(ctx, run.ID, status, outputPath, sizeBytes, filesBackedUp, errorMessage); err != nil {
		slog.Error("failed to complete backup run record", "error", err)
	}

	// Apply retention policy
	s.applyRetentionPolicy(ctx, schedule)
}

// sanitizeErrorMessage removes potentially sensitive information from error messages.
func sanitizeErrorMessage(errMsg string) string {
	// Remove absolute paths from error messages
	// Look for common path patterns and replace them with generic placeholders
	sanitized := errMsg

	// Remove Unix-style absolute paths
	pathRegex := regexp.MustCompile(`/[a-zA-Z0-9_\-./]+`)
	sanitized = pathRegex.ReplaceAllStringFunc(sanitized, func(path string) string {
		// Keep just the basename or a generic placeholder
		base := filepath.Base(path)
		if base == "." || base == "/" || base == "" {
			return "[path]"
		}
		return "[.../" + base + "]"
	})

	return sanitized
}

// performBackup executes the actual backup operation.
func (s *Scheduler) performBackup(ctx context.Context, mode string) *BackupResult {
	// Determine backup directory
	backupDir := s.cfg.BackupDir
	if backupDir == "" {
		backupDir = filepath.Join(s.cfg.DataDir, "backups")
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return &BackupResult{
			Success: false,
			Error:   "failed to create backup directory",
		}
	}

	// Create backup options
	opts := CreateOptions{
		Mode:             BackupMode(mode),
		DBPath:           s.cfg.DBPath,
		UploadsDir:       s.cfg.UploadDir,
		OutputDir:        backupDir,
		EncryptionKey:    s.cfg.EncryptionKey,
		SafeShareVersion: s.cfg.Version,
		ProgressCallback: func(current, total int, description string) {
			slog.Debug("backup progress", "current", current, "total", total, "description", description)
		},
	}

	result, err := Create(opts)
	if err != nil {
		return &BackupResult{
			Success: false,
			Error:   err.Error(),
		}
	}
	return result
}

// applyRetentionPolicy removes old backups based on the schedule's retention policy.
func (s *Scheduler) applyRetentionPolicy(ctx context.Context, schedule *repository.BackupSchedule) {
	if schedule.RetentionDays <= 0 {
		// 0 means unlimited retention
		return
	}

	cutoffTime := time.Now().AddDate(0, 0, -schedule.RetentionDays)

	// Delete old backup run records
	deleted, err := s.repos.BackupScheduler.DeleteOldRuns(ctx, cutoffTime)
	if err != nil {
		slog.Error("failed to delete old backup runs", "error", err)
	} else if deleted > 0 {
		slog.Info("deleted old backup run records", "count", deleted, "cutoff", cutoffTime)
	}

	// Also clean up old backup directories
	s.cleanupOldBackupDirectories(cutoffTime)
}

// cleanupOldBackupDirectories removes backup directories older than the cutoff time.
// Uses strict validation to prevent path traversal attacks.
func (s *Scheduler) cleanupOldBackupDirectories(cutoffTime time.Time) {
	backupDir := s.cfg.BackupDir
	if backupDir == "" {
		backupDir = filepath.Join(s.cfg.DataDir, "backups")
	}

	// Resolve to absolute path for safety
	absBackupDir, err := filepath.Abs(backupDir)
	if err != nil {
		slog.Error("failed to resolve backup directory path", "error", err)
		return
	}

	entries, err := os.ReadDir(absBackupDir)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Error("failed to read backup directory", "error", err)
		}
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		dirName := entry.Name()

		// Strict validation: only delete directories matching backup-YYYYMMDD-HHMMSS pattern
		// This prevents any path traversal or accidental deletion of non-backup directories
		if !backupDirNameRegex.MatchString(dirName) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoffTime) {
			// Construct path safely and verify it's within backup directory
			backupPath := filepath.Join(absBackupDir, dirName)

			// Double-check the path is still within backup directory (defense in depth)
			absBackupPath, err := filepath.Abs(backupPath)
			if err != nil {
				slog.Warn("skipping backup cleanup: failed to resolve path", "dir", dirName)
				continue
			}

			if !strings.HasPrefix(absBackupPath, absBackupDir+string(filepath.Separator)) {
				slog.Warn("skipping backup cleanup: path escapes backup directory", "dir", dirName)
				continue
			}

			if err := os.RemoveAll(absBackupPath); err != nil {
				slog.Error("failed to remove old backup directory", "path", dirName, "error", err)
			} else {
				slog.Info("removed old backup directory", "path", dirName, "age_days", int(time.Since(info.ModTime()).Hours()/24))
			}
		}
	}
}

// calculateNextRun calculates the next run time based on a cron expression.
// Uses bounded iteration to prevent integer overflow.
func (s *Scheduler) calculateNextRun(cronExpr string, from time.Time) *time.Time {
	// Parse cron expression
	fields := strings.Fields(cronExpr)
	if len(fields) != 5 {
		// Default to next day at 2 AM if parsing fails
		next := time.Date(from.Year(), from.Month(), from.Day()+1, 2, 0, 0, 0, from.Location())
		return &next
	}

	minute, err1 := strconv.Atoi(fields[0])
	hour, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		// Default to next day at 2 AM if parsing fails
		next := time.Date(from.Year(), from.Month(), from.Day()+1, 2, 0, 0, 0, from.Location())
		return &next
	}

	// Bounds check to prevent unexpected behavior
	if minute < 0 || minute > 59 || hour < 0 || hour > 23 {
		next := time.Date(from.Year(), from.Month(), from.Day()+1, 2, 0, 0, 0, from.Location())
		return &next
	}

	dayOfMonth := fields[2]
	month := fields[3]
	dayOfWeek := fields[4]

	next := from.Add(time.Minute).Truncate(time.Minute)

	// Find next matching time with bounded iteration (max 1 year)
	// Use a constant to prevent integer overflow
	const maxIterations = 525960 // 365.25 days * 24 hours * 60 minutes
	for i := 0; i < maxIterations; i++ {
		if next.Minute() == minute && next.Hour() == hour {
			// Check day of week (0 = Sunday)
			if dayOfWeek != "*" {
				dow, err := strconv.Atoi(dayOfWeek)
				if err == nil && dow >= 0 && dow <= 6 {
					if int(next.Weekday()) != dow {
						next = next.Add(time.Minute)
						continue
					}
				}
			}
			// Check day of month
			if dayOfMonth != "*" {
				dom, err := strconv.Atoi(dayOfMonth)
				if err == nil && dom >= 1 && dom <= 31 {
					if next.Day() != dom {
						next = next.Add(time.Minute)
						continue
					}
				}
			}
			// Check month
			if month != "*" {
				m, err := strconv.Atoi(month)
				if err == nil && m >= 1 && m <= 12 {
					if int(next.Month()) != m {
						next = next.Add(time.Minute)
						continue
					}
				}
			}
			return &next
		}
		next = next.Add(time.Minute)
	}

	// Fallback: next day at specified time
	next = time.Date(from.Year(), from.Month(), from.Day()+1, hour, minute, 0, 0, from.Location())
	return &next
}

// TriggerBackup triggers a manual backup with the specified mode.
// Returns the backup run record.
// Uses mutex to prevent race condition between check and execution.
func (s *Scheduler) TriggerBackup(ctx context.Context, mode string, triggerType repository.BackupTriggerType) (*repository.BackupRun, error) {
	// Acquire backup mutex to prevent race condition
	s.backupMu.Lock()
	defer s.backupMu.Unlock()

	// Check if another backup is already running (under mutex protection)
	runningBackup, err := s.repos.BackupScheduler.GetRunningBackup(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check backup status: %w", err)
	}
	if runningBackup != nil {
		return nil, ErrBackupAlreadyRunning
	}

	// Create backup run record
	run := &repository.BackupRun{
		TriggerType: triggerType,
		Mode:        mode,
	}
	if err := s.repos.BackupScheduler.CreateRun(ctx, run); err != nil {
		return nil, fmt.Errorf("failed to create backup run: %w", err)
	}

	// Update run status to running
	run.Status = repository.BackupRunStatusRunning
	if err := s.repos.BackupScheduler.UpdateRun(ctx, run); err != nil {
		return nil, fmt.Errorf("failed to update backup status: %w", err)
	}

	// Track the backup goroutine with WaitGroup for graceful shutdown
	s.backupWg.Add(1)

	// Execute backup in background
	go func() {
		defer s.backupWg.Done()

		result := s.performBackup(context.Background(), mode)

		var status repository.BackupRunStatus
		var errorMessage string
		var outputPath string
		var sizeBytes int64
		var filesBackedUp int

		if result.Success {
			status = repository.BackupRunStatusCompleted
			outputPath = result.BackupPath
			if result.Manifest != nil {
				sizeBytes = result.Manifest.Stats.TotalSizeBytes
				filesBackedUp = result.Manifest.Stats.FilesBackedUp
			}
			slog.Info("manual backup completed successfully",
				"run_id", run.ID,
				"output_path", outputPath,
				"size_bytes", sizeBytes,
				"duration", result.DurationString)
		} else {
			status = repository.BackupRunStatusFailed
			errorMessage = sanitizeErrorMessage(result.Error)
			slog.Error("manual backup failed",
				"run_id", run.ID,
				"error", result.Error, // Log full error internally
				"duration", result.DurationString)
		}

		if err := s.repos.BackupScheduler.CompleteRun(context.Background(), run.ID, status, outputPath, sizeBytes, filesBackedUp, errorMessage); err != nil {
			slog.Error("failed to complete backup run record", "error", err)
		}
	}()

	return run, nil
}
