// Package mock provides mock implementations of repository interfaces for testing.
package mock

import (
	"context"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// BackupSchedulerRepository is a mock implementation of repository.BackupSchedulerRepository.
type BackupSchedulerRepository struct {
	mu sync.RWMutex

	// Storage for test data
	schedules   map[int64]*repository.BackupSchedule
	runs        map[int64]*repository.BackupRun
	nextID      int64
	nextRunID   int64

	// Function overrides for custom behavior in tests
	CreateScheduleFunc         func(ctx context.Context, schedule *repository.BackupSchedule) error
	GetScheduleFunc            func(ctx context.Context, id int64) (*repository.BackupSchedule, error)
	GetScheduleByNameFunc      func(ctx context.Context, name string) (*repository.BackupSchedule, error)
	UpdateScheduleFunc         func(ctx context.Context, schedule *repository.BackupSchedule) error
	DeleteScheduleFunc         func(ctx context.Context, id int64) error
	ListSchedulesFunc          func(ctx context.Context) ([]repository.BackupSchedule, error)
	GetDueSchedulesFunc        func(ctx context.Context, now time.Time) ([]repository.BackupSchedule, error)
	UpdateScheduleLastRunFunc  func(ctx context.Context, id int64, lastRunAt time.Time, nextRunAt time.Time) error
	CreateRunFunc              func(ctx context.Context, run *repository.BackupRun) error
	GetRunFunc                 func(ctx context.Context, id int64) (*repository.BackupRun, error)
	UpdateRunFunc              func(ctx context.Context, run *repository.BackupRun) error
	CompleteRunFunc            func(ctx context.Context, id int64, status repository.BackupRunStatus, outputPath string, sizeBytes int64, filesBackedUp int, errorMessage string) error
	ListRunsFunc               func(ctx context.Context, filter repository.BackupRunFilter) ([]repository.BackupRun, error)
	GetLastRunForScheduleFunc  func(ctx context.Context, scheduleID int64) (*repository.BackupRun, error)
	DeleteOldRunsFunc          func(ctx context.Context, olderThan time.Time) (int64, error)
	GetRunStatsFunc            func(ctx context.Context) (*repository.BackupRunStats, error)
	GetRunningBackupFunc       func(ctx context.Context) (*repository.BackupRun, error)
}

// NewBackupSchedulerRepository creates a new mock BackupSchedulerRepository.
func NewBackupSchedulerRepository() *BackupSchedulerRepository {
	return &BackupSchedulerRepository{
		schedules: make(map[int64]*repository.BackupSchedule),
		runs:      make(map[int64]*repository.BackupRun),
		nextID:    1,
		nextRunID: 1,
	}
}

// CreateSchedule implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) CreateSchedule(ctx context.Context, schedule *repository.BackupSchedule) error {
	if m.CreateScheduleFunc != nil {
		return m.CreateScheduleFunc(ctx, schedule)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	schedule.ID = m.nextID
	m.nextID++
	schedule.CreatedAt = time.Now()
	schedule.UpdatedAt = time.Now()
	m.schedules[schedule.ID] = schedule
	return nil
}

// GetSchedule implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) GetSchedule(ctx context.Context, id int64) (*repository.BackupSchedule, error) {
	if m.GetScheduleFunc != nil {
		return m.GetScheduleFunc(ctx, id)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if schedule, ok := m.schedules[id]; ok {
		return schedule, nil
	}
	return nil, nil
}

// GetScheduleByName implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) GetScheduleByName(ctx context.Context, name string) (*repository.BackupSchedule, error) {
	if m.GetScheduleByNameFunc != nil {
		return m.GetScheduleByNameFunc(ctx, name)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, schedule := range m.schedules {
		if schedule.Name == name {
			return schedule, nil
		}
	}
	return nil, nil
}

// UpdateSchedule implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) UpdateSchedule(ctx context.Context, schedule *repository.BackupSchedule) error {
	if m.UpdateScheduleFunc != nil {
		return m.UpdateScheduleFunc(ctx, schedule)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.schedules[schedule.ID]; ok {
		schedule.UpdatedAt = time.Now()
		m.schedules[schedule.ID] = schedule
	}
	return nil
}

// DeleteSchedule implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) DeleteSchedule(ctx context.Context, id int64) error {
	if m.DeleteScheduleFunc != nil {
		return m.DeleteScheduleFunc(ctx, id)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.schedules, id)
	return nil
}

// ListSchedules implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) ListSchedules(ctx context.Context) ([]repository.BackupSchedule, error) {
	if m.ListSchedulesFunc != nil {
		return m.ListSchedulesFunc(ctx)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []repository.BackupSchedule
	for _, schedule := range m.schedules {
		result = append(result, *schedule)
	}
	return result, nil
}

// GetDueSchedules implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) GetDueSchedules(ctx context.Context, now time.Time) ([]repository.BackupSchedule, error) {
	if m.GetDueSchedulesFunc != nil {
		return m.GetDueSchedulesFunc(ctx, now)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []repository.BackupSchedule
	for _, schedule := range m.schedules {
		if schedule.Enabled && schedule.NextRunAt != nil && !schedule.NextRunAt.After(now) {
			result = append(result, *schedule)
		}
	}
	return result, nil
}

// UpdateScheduleLastRun implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) UpdateScheduleLastRun(ctx context.Context, id int64, lastRunAt time.Time, nextRunAt time.Time) error {
	if m.UpdateScheduleLastRunFunc != nil {
		return m.UpdateScheduleLastRunFunc(ctx, id, lastRunAt, nextRunAt)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if schedule, ok := m.schedules[id]; ok {
		schedule.LastRunAt = &lastRunAt
		schedule.NextRunAt = &nextRunAt
		schedule.UpdatedAt = time.Now()
	}
	return nil
}

// CreateRun implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) CreateRun(ctx context.Context, run *repository.BackupRun) error {
	if m.CreateRunFunc != nil {
		return m.CreateRunFunc(ctx, run)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	run.ID = m.nextRunID
	m.nextRunID++
	m.runs[run.ID] = run
	return nil
}

// GetRun implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) GetRun(ctx context.Context, id int64) (*repository.BackupRun, error) {
	if m.GetRunFunc != nil {
		return m.GetRunFunc(ctx, id)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if run, ok := m.runs[id]; ok {
		return run, nil
	}
	return nil, nil
}

// UpdateRun implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) UpdateRun(ctx context.Context, run *repository.BackupRun) error {
	if m.UpdateRunFunc != nil {
		return m.UpdateRunFunc(ctx, run)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.runs[run.ID]; ok {
		m.runs[run.ID] = run
	}
	return nil
}

// CompleteRun implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) CompleteRun(ctx context.Context, id int64, status repository.BackupRunStatus, outputPath string, sizeBytes int64, filesBackedUp int, errorMessage string) error {
	if m.CompleteRunFunc != nil {
		return m.CompleteRunFunc(ctx, id, status, outputPath, sizeBytes, filesBackedUp, errorMessage)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if run, ok := m.runs[id]; ok {
		run.Status = status
		run.OutputPath = outputPath
		run.SizeBytes = sizeBytes
		run.FilesBackedUp = filesBackedUp
		run.ErrorMessage = errorMessage
		completedAt := time.Now()
		run.CompletedAt = &completedAt
		run.DurationMs = int(completedAt.Sub(run.StartedAt).Milliseconds())
	}
	return nil
}

// ListRuns implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) ListRuns(ctx context.Context, filter repository.BackupRunFilter) ([]repository.BackupRun, error) {
	if m.ListRunsFunc != nil {
		return m.ListRunsFunc(ctx, filter)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []repository.BackupRun
	for _, run := range m.runs {
		// Apply filters
		if filter.ScheduleID != nil && (run.ScheduleID == nil || *run.ScheduleID != *filter.ScheduleID) {
			continue
		}
		if filter.Status != nil && run.Status != *filter.Status {
			continue
		}
		if filter.TriggerType != nil && run.TriggerType != *filter.TriggerType {
			continue
		}
		result = append(result, *run)
	}

	// Apply limit
	limit := filter.Limit
	if limit == 0 {
		limit = 100
	}
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// GetLastRunForSchedule implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) GetLastRunForSchedule(ctx context.Context, scheduleID int64) (*repository.BackupRun, error) {
	if m.GetLastRunForScheduleFunc != nil {
		return m.GetLastRunForScheduleFunc(ctx, scheduleID)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastRun *repository.BackupRun
	for _, run := range m.runs {
		if run.ScheduleID != nil && *run.ScheduleID == scheduleID {
			if lastRun == nil || run.StartedAt.After(lastRun.StartedAt) {
				lastRun = run
			}
		}
	}
	return lastRun, nil
}

// DeleteOldRuns implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) DeleteOldRuns(ctx context.Context, olderThan time.Time) (int64, error) {
	if m.DeleteOldRunsFunc != nil {
		return m.DeleteOldRunsFunc(ctx, olderThan)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var deleted int64
	for id, run := range m.runs {
		if run.StartedAt.Before(olderThan) {
			delete(m.runs, id)
			deleted++
		}
	}
	return deleted, nil
}

// GetRunStats implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) GetRunStats(ctx context.Context) (*repository.BackupRunStats, error) {
	if m.GetRunStatsFunc != nil {
		return m.GetRunStatsFunc(ctx)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &repository.BackupRunStats{}
	for _, run := range m.runs {
		stats.TotalRuns++
		if run.Status == repository.BackupRunStatusCompleted {
			stats.SuccessfulRuns++
			stats.TotalSizeBytes += run.SizeBytes
			if run.CompletedAt != nil && (stats.LastSuccessfulAt == nil || run.CompletedAt.After(*stats.LastSuccessfulAt)) {
				stats.LastSuccessfulAt = run.CompletedAt
			}
		} else if run.Status == repository.BackupRunStatusFailed {
			stats.FailedRuns++
			if run.CompletedAt != nil && (stats.LastFailedAt == nil || run.CompletedAt.After(*stats.LastFailedAt)) {
				stats.LastFailedAt = run.CompletedAt
			}
		}
	}
	return stats, nil
}

// GetRunningBackup implements repository.BackupSchedulerRepository.
func (m *BackupSchedulerRepository) GetRunningBackup(ctx context.Context) (*repository.BackupRun, error) {
	if m.GetRunningBackupFunc != nil {
		return m.GetRunningBackupFunc(ctx)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, run := range m.runs {
		if run.Status == repository.BackupRunStatusRunning {
			return run, nil
		}
	}
	return nil, nil
}

// Ensure BackupSchedulerRepository implements repository.BackupSchedulerRepository.
var _ repository.BackupSchedulerRepository = (*BackupSchedulerRepository)(nil)
