package mock

import (
	"context"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

func TestNewBackupSchedulerRepository(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	if repo == nil {
		t.Fatal("NewBackupSchedulerRepository returned nil")
	}
	if repo.schedules == nil {
		t.Error("schedules map should be initialized")
	}
	if repo.runs == nil {
		t.Error("runs map should be initialized")
	}
	if repo.nextID != 1 {
		t.Errorf("nextID should be 1, got %d", repo.nextID)
	}
}

func TestBackupSchedulerRepository_CreateSchedule(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	schedule := &repository.BackupSchedule{
		Name:     "daily-backup",
		Schedule: "0 2 * * *",
		Mode:     "full",
		Enabled:  true,
	}

	err := repo.CreateSchedule(ctx, schedule)
	if err != nil {
		t.Fatalf("CreateSchedule failed: %v", err)
	}
	if schedule.ID == 0 {
		t.Error("schedule ID should be assigned")
	}
	if schedule.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestBackupSchedulerRepository_CreateSchedule_WithFunc(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	customErr := repository.ErrNotFound
	repo.CreateScheduleFunc = func(ctx context.Context, schedule *repository.BackupSchedule) error {
		return customErr
	}

	schedule := &repository.BackupSchedule{Name: "test"}
	err := repo.CreateSchedule(ctx, schedule)
	if err != customErr {
		t.Errorf("expected custom error, got %v", err)
	}
}

func TestBackupSchedulerRepository_GetSchedule(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	// Create a schedule first
	schedule := &repository.BackupSchedule{
		Name: "test-schedule",
		Mode: "full",
	}
	_ = repo.CreateSchedule(ctx, schedule)

	// Get it back
	retrieved, err := repo.GetSchedule(ctx, schedule.ID)
	if err != nil {
		t.Fatalf("GetSchedule failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("retrieved schedule should not be nil")
	}
	if retrieved.Name != "test-schedule" {
		t.Errorf("expected name test-schedule, got %s", retrieved.Name)
	}

	// Get non-existent
	notFound, err := repo.GetSchedule(ctx, 999)
	if err != nil {
		t.Fatalf("GetSchedule should not error for non-existent: %v", err)
	}
	if notFound != nil {
		t.Error("should return nil for non-existent schedule")
	}
}

func TestBackupSchedulerRepository_GetScheduleByName(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	schedule := &repository.BackupSchedule{
		Name: "unique-name",
		Mode: "config",
	}
	_ = repo.CreateSchedule(ctx, schedule)

	// Find by name
	found, err := repo.GetScheduleByName(ctx, "unique-name")
	if err != nil {
		t.Fatalf("GetScheduleByName failed: %v", err)
	}
	if found == nil {
		t.Fatal("should find schedule by name")
	}
	if found.ID != schedule.ID {
		t.Error("should find the correct schedule")
	}

	// Not found
	notFound, err := repo.GetScheduleByName(ctx, "non-existent")
	if err != nil {
		t.Fatalf("should not error: %v", err)
	}
	if notFound != nil {
		t.Error("should return nil for non-existent name")
	}
}

func TestBackupSchedulerRepository_UpdateSchedule(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	schedule := &repository.BackupSchedule{
		Name: "original",
		Mode: "full",
	}
	_ = repo.CreateSchedule(ctx, schedule)

	// Update
	schedule.Name = "updated"
	err := repo.UpdateSchedule(ctx, schedule)
	if err != nil {
		t.Fatalf("UpdateSchedule failed: %v", err)
	}

	// Verify update
	retrieved, _ := repo.GetSchedule(ctx, schedule.ID)
	if retrieved.Name != "updated" {
		t.Errorf("expected name updated, got %s", retrieved.Name)
	}
}

func TestBackupSchedulerRepository_DeleteSchedule(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	schedule := &repository.BackupSchedule{
		Name: "to-delete",
		Mode: "full",
	}
	_ = repo.CreateSchedule(ctx, schedule)

	// Delete
	err := repo.DeleteSchedule(ctx, schedule.ID)
	if err != nil {
		t.Fatalf("DeleteSchedule failed: %v", err)
	}

	// Verify deleted
	retrieved, _ := repo.GetSchedule(ctx, schedule.ID)
	if retrieved != nil {
		t.Error("schedule should be deleted")
	}
}

func TestBackupSchedulerRepository_ListSchedules(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	// Create multiple schedules
	for i := 0; i < 3; i++ {
		_ = repo.CreateSchedule(ctx, &repository.BackupSchedule{
			Name: "schedule",
			Mode: "full",
		})
	}

	list, err := repo.ListSchedules(ctx)
	if err != nil {
		t.Fatalf("ListSchedules failed: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 schedules, got %d", len(list))
	}
}

func TestBackupSchedulerRepository_GetDueSchedules(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	// Create due schedule
	dueSchedule := &repository.BackupSchedule{
		Name:      "due",
		Mode:      "full",
		Enabled:   true,
		NextRunAt: &past,
	}
	_ = repo.CreateSchedule(ctx, dueSchedule)

	// Create not-due schedule
	notDueSchedule := &repository.BackupSchedule{
		Name:      "not-due",
		Mode:      "full",
		Enabled:   true,
		NextRunAt: &future,
	}
	_ = repo.CreateSchedule(ctx, notDueSchedule)

	// Create disabled schedule (should not be returned)
	disabledSchedule := &repository.BackupSchedule{
		Name:      "disabled",
		Mode:      "full",
		Enabled:   false,
		NextRunAt: &past,
	}
	_ = repo.CreateSchedule(ctx, disabledSchedule)

	due, err := repo.GetDueSchedules(ctx, time.Now())
	if err != nil {
		t.Fatalf("GetDueSchedules failed: %v", err)
	}
	if len(due) != 1 {
		t.Errorf("expected 1 due schedule, got %d", len(due))
	}
	if len(due) > 0 && due[0].Name != "due" {
		t.Errorf("expected due schedule, got %s", due[0].Name)
	}
}

func TestBackupSchedulerRepository_UpdateScheduleLastRun(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	schedule := &repository.BackupSchedule{
		Name: "test",
		Mode: "full",
	}
	_ = repo.CreateSchedule(ctx, schedule)

	lastRun := time.Now()
	nextRun := time.Now().Add(24 * time.Hour)

	err := repo.UpdateScheduleLastRun(ctx, schedule.ID, lastRun, nextRun)
	if err != nil {
		t.Fatalf("UpdateScheduleLastRun failed: %v", err)
	}

	retrieved, _ := repo.GetSchedule(ctx, schedule.ID)
	if retrieved.LastRunAt == nil || !retrieved.LastRunAt.Equal(lastRun) {
		t.Error("LastRunAt should be updated")
	}
	if retrieved.NextRunAt == nil || !retrieved.NextRunAt.Equal(nextRun) {
		t.Error("NextRunAt should be updated")
	}
}

func TestBackupSchedulerRepository_CreateRun(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	run := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusRunning,
		StartedAt:   time.Now(),
	}

	err := repo.CreateRun(ctx, run)
	if err != nil {
		t.Fatalf("CreateRun failed: %v", err)
	}
	if run.ID == 0 {
		t.Error("run ID should be assigned")
	}
}

func TestBackupSchedulerRepository_GetRun(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	run := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusRunning,
		StartedAt:   time.Now(),
	}
	_ = repo.CreateRun(ctx, run)

	retrieved, err := repo.GetRun(ctx, run.ID)
	if err != nil {
		t.Fatalf("GetRun failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("retrieved run should not be nil")
	}
	if retrieved.TriggerType != repository.BackupTriggerManual {
		t.Errorf("expected manual trigger, got %s", retrieved.TriggerType)
	}
}

func TestBackupSchedulerRepository_UpdateRun(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	run := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusRunning,
		StartedAt:   time.Now(),
	}
	_ = repo.CreateRun(ctx, run)

	run.Status = repository.BackupRunStatusCompleted
	err := repo.UpdateRun(ctx, run)
	if err != nil {
		t.Fatalf("UpdateRun failed: %v", err)
	}

	retrieved, _ := repo.GetRun(ctx, run.ID)
	if retrieved.Status != repository.BackupRunStatusCompleted {
		t.Error("status should be updated")
	}
}

func TestBackupSchedulerRepository_CompleteRun(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	run := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusRunning,
		StartedAt:   time.Now(),
	}
	_ = repo.CreateRun(ctx, run)

	err := repo.CompleteRun(ctx, run.ID, repository.BackupRunStatusCompleted, "/path/to/backup", 1024, 10, "")
	if err != nil {
		t.Fatalf("CompleteRun failed: %v", err)
	}

	retrieved, _ := repo.GetRun(ctx, run.ID)
	if retrieved.Status != repository.BackupRunStatusCompleted {
		t.Error("status should be completed")
	}
	if retrieved.OutputPath != "/path/to/backup" {
		t.Error("output path should be set")
	}
	if retrieved.SizeBytes != 1024 {
		t.Error("size bytes should be set")
	}
	if retrieved.FilesBackedUp != 10 {
		t.Error("files backed up should be set")
	}
	if retrieved.CompletedAt == nil {
		t.Error("CompletedAt should be set")
	}
}

func TestBackupSchedulerRepository_ListRuns(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	scheduleID := int64(1)

	// Create multiple runs
	for i := 0; i < 5; i++ {
		run := &repository.BackupRun{
			TriggerType: repository.BackupTriggerScheduled,
			Mode:        "full",
			Status:      repository.BackupRunStatusCompleted,
			StartedAt:   time.Now(),
			ScheduleID:  &scheduleID,
		}
		_ = repo.CreateRun(ctx, run)
	}

	// List without filter
	runs, err := repo.ListRuns(ctx, repository.BackupRunFilter{})
	if err != nil {
		t.Fatalf("ListRuns failed: %v", err)
	}
	if len(runs) != 5 {
		t.Errorf("expected 5 runs, got %d", len(runs))
	}

	// List with schedule filter
	runs, err = repo.ListRuns(ctx, repository.BackupRunFilter{ScheduleID: &scheduleID})
	if err != nil {
		t.Fatalf("ListRuns with filter failed: %v", err)
	}
	if len(runs) != 5 {
		t.Errorf("expected 5 runs with filter, got %d", len(runs))
	}

	// List with limit
	runs, err = repo.ListRuns(ctx, repository.BackupRunFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ListRuns with limit failed: %v", err)
	}
	if len(runs) != 2 {
		t.Errorf("expected 2 runs with limit, got %d", len(runs))
	}
}

func TestBackupSchedulerRepository_ListRuns_WithFilters(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	// Create runs with different statuses
	completedRun := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusCompleted,
		StartedAt:   time.Now(),
	}
	_ = repo.CreateRun(ctx, completedRun)

	failedRun := &repository.BackupRun{
		TriggerType: repository.BackupTriggerScheduled,
		Mode:        "full",
		Status:      repository.BackupRunStatusFailed,
		StartedAt:   time.Now(),
	}
	_ = repo.CreateRun(ctx, failedRun)

	// Filter by status
	status := repository.BackupRunStatusCompleted
	runs, _ := repo.ListRuns(ctx, repository.BackupRunFilter{Status: &status})
	if len(runs) != 1 {
		t.Errorf("expected 1 completed run, got %d", len(runs))
	}

	// Filter by trigger type
	triggerType := repository.BackupTriggerManual
	runs, _ = repo.ListRuns(ctx, repository.BackupRunFilter{TriggerType: &triggerType})
	if len(runs) != 1 {
		t.Errorf("expected 1 manual run, got %d", len(runs))
	}
}

func TestBackupSchedulerRepository_GetLastRunForSchedule(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	scheduleID := int64(1)

	// Create runs at different times
	oldRun := &repository.BackupRun{
		TriggerType: repository.BackupTriggerScheduled,
		Mode:        "full",
		Status:      repository.BackupRunStatusCompleted,
		StartedAt:   time.Now().Add(-2 * time.Hour),
		ScheduleID:  &scheduleID,
	}
	_ = repo.CreateRun(ctx, oldRun)

	newRun := &repository.BackupRun{
		TriggerType: repository.BackupTriggerScheduled,
		Mode:        "full",
		Status:      repository.BackupRunStatusCompleted,
		StartedAt:   time.Now(),
		ScheduleID:  &scheduleID,
	}
	_ = repo.CreateRun(ctx, newRun)

	lastRun, err := repo.GetLastRunForSchedule(ctx, scheduleID)
	if err != nil {
		t.Fatalf("GetLastRunForSchedule failed: %v", err)
	}
	if lastRun == nil {
		t.Fatal("lastRun should not be nil")
	}
	if lastRun.ID != newRun.ID {
		t.Error("should return the most recent run")
	}
}

func TestBackupSchedulerRepository_DeleteOldRuns(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	// Create old run
	oldRun := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusCompleted,
		StartedAt:   time.Now().Add(-48 * time.Hour),
	}
	_ = repo.CreateRun(ctx, oldRun)

	// Create recent run
	newRun := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusCompleted,
		StartedAt:   time.Now(),
	}
	_ = repo.CreateRun(ctx, newRun)

	deleted, err := repo.DeleteOldRuns(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("DeleteOldRuns failed: %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	// Verify old run is deleted
	runs, _ := repo.ListRuns(ctx, repository.BackupRunFilter{})
	if len(runs) != 1 {
		t.Errorf("expected 1 remaining run, got %d", len(runs))
	}
}

func TestBackupSchedulerRepository_GetRunStats(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	// Create completed runs
	for i := 0; i < 3; i++ {
		run := &repository.BackupRun{
			TriggerType: repository.BackupTriggerManual,
			Mode:        "full",
			Status:      repository.BackupRunStatusCompleted,
			StartedAt:   time.Now(),
			SizeBytes:   1024,
		}
		_ = repo.CreateRun(ctx, run)
		completedAt := time.Now()
		repo.runs[run.ID].CompletedAt = &completedAt
	}

	// Create failed run
	failedRun := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusFailed,
		StartedAt:   time.Now(),
	}
	_ = repo.CreateRun(ctx, failedRun)
	failedAt := time.Now()
	repo.runs[failedRun.ID].CompletedAt = &failedAt

	stats, err := repo.GetRunStats(ctx)
	if err != nil {
		t.Fatalf("GetRunStats failed: %v", err)
	}
	if stats.TotalRuns != 4 {
		t.Errorf("expected 4 total runs, got %d", stats.TotalRuns)
	}
	if stats.SuccessfulRuns != 3 {
		t.Errorf("expected 3 successful runs, got %d", stats.SuccessfulRuns)
	}
	if stats.FailedRuns != 1 {
		t.Errorf("expected 1 failed run, got %d", stats.FailedRuns)
	}
	if stats.TotalSizeBytes != 3072 {
		t.Errorf("expected 3072 total size, got %d", stats.TotalSizeBytes)
	}
}

func TestBackupSchedulerRepository_GetRunningBackup(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	// No running backup initially
	running, err := repo.GetRunningBackup(ctx)
	if err != nil {
		t.Fatalf("GetRunningBackup failed: %v", err)
	}
	if running != nil {
		t.Error("should return nil when no backup is running")
	}

	// Create running backup
	runningRun := &repository.BackupRun{
		TriggerType: repository.BackupTriggerManual,
		Mode:        "full",
		Status:      repository.BackupRunStatusRunning,
		StartedAt:   time.Now(),
	}
	_ = repo.CreateRun(ctx, runningRun)

	running, err = repo.GetRunningBackup(ctx)
	if err != nil {
		t.Fatalf("GetRunningBackup failed: %v", err)
	}
	if running == nil {
		t.Fatal("should return the running backup")
	}
	if running.ID != runningRun.ID {
		t.Error("should return correct running backup")
	}
}

func TestBackupSchedulerRepository_FunctionOverrides(t *testing.T) {
	repo := NewBackupSchedulerRepository()
	ctx := context.Background()

	// Test all function overrides
	t.Run("GetScheduleFunc", func(t *testing.T) {
		customSchedule := &repository.BackupSchedule{ID: 999, Name: "custom"}
		repo.GetScheduleFunc = func(ctx context.Context, id int64) (*repository.BackupSchedule, error) {
			return customSchedule, nil
		}
		result, _ := repo.GetSchedule(ctx, 1)
		if result != customSchedule {
			t.Error("should use custom function")
		}
		repo.GetScheduleFunc = nil
	})

	t.Run("GetScheduleByNameFunc", func(t *testing.T) {
		repo.GetScheduleByNameFunc = func(ctx context.Context, name string) (*repository.BackupSchedule, error) {
			return &repository.BackupSchedule{Name: "override"}, nil
		}
		result, _ := repo.GetScheduleByName(ctx, "test")
		if result.Name != "override" {
			t.Error("should use custom function")
		}
		repo.GetScheduleByNameFunc = nil
	})

	t.Run("UpdateScheduleFunc", func(t *testing.T) {
		called := false
		repo.UpdateScheduleFunc = func(ctx context.Context, schedule *repository.BackupSchedule) error {
			called = true
			return nil
		}
		_ = repo.UpdateSchedule(ctx, &repository.BackupSchedule{})
		if !called {
			t.Error("should use custom function")
		}
		repo.UpdateScheduleFunc = nil
	})

	t.Run("DeleteScheduleFunc", func(t *testing.T) {
		called := false
		repo.DeleteScheduleFunc = func(ctx context.Context, id int64) error {
			called = true
			return nil
		}
		_ = repo.DeleteSchedule(ctx, 1)
		if !called {
			t.Error("should use custom function")
		}
		repo.DeleteScheduleFunc = nil
	})

	t.Run("ListSchedulesFunc", func(t *testing.T) {
		repo.ListSchedulesFunc = func(ctx context.Context) ([]repository.BackupSchedule, error) {
			return []repository.BackupSchedule{{Name: "listed"}}, nil
		}
		result, _ := repo.ListSchedules(ctx)
		if len(result) != 1 || result[0].Name != "listed" {
			t.Error("should use custom function")
		}
		repo.ListSchedulesFunc = nil
	})

	t.Run("GetDueSchedulesFunc", func(t *testing.T) {
		repo.GetDueSchedulesFunc = func(ctx context.Context, now time.Time) ([]repository.BackupSchedule, error) {
			return []repository.BackupSchedule{{Name: "due"}}, nil
		}
		result, _ := repo.GetDueSchedules(ctx, time.Now())
		if len(result) != 1 || result[0].Name != "due" {
			t.Error("should use custom function")
		}
		repo.GetDueSchedulesFunc = nil
	})

	t.Run("UpdateScheduleLastRunFunc", func(t *testing.T) {
		called := false
		repo.UpdateScheduleLastRunFunc = func(ctx context.Context, id int64, lastRunAt time.Time, nextRunAt time.Time) error {
			called = true
			return nil
		}
		_ = repo.UpdateScheduleLastRun(ctx, 1, time.Now(), time.Now())
		if !called {
			t.Error("should use custom function")
		}
		repo.UpdateScheduleLastRunFunc = nil
	})

	t.Run("CreateRunFunc", func(t *testing.T) {
		called := false
		repo.CreateRunFunc = func(ctx context.Context, run *repository.BackupRun) error {
			called = true
			return nil
		}
		_ = repo.CreateRun(ctx, &repository.BackupRun{})
		if !called {
			t.Error("should use custom function")
		}
		repo.CreateRunFunc = nil
	})

	t.Run("GetRunFunc", func(t *testing.T) {
		repo.GetRunFunc = func(ctx context.Context, id int64) (*repository.BackupRun, error) {
			return &repository.BackupRun{ID: 999}, nil
		}
		result, _ := repo.GetRun(ctx, 1)
		if result.ID != 999 {
			t.Error("should use custom function")
		}
		repo.GetRunFunc = nil
	})

	t.Run("UpdateRunFunc", func(t *testing.T) {
		called := false
		repo.UpdateRunFunc = func(ctx context.Context, run *repository.BackupRun) error {
			called = true
			return nil
		}
		_ = repo.UpdateRun(ctx, &repository.BackupRun{})
		if !called {
			t.Error("should use custom function")
		}
		repo.UpdateRunFunc = nil
	})

	t.Run("CompleteRunFunc", func(t *testing.T) {
		called := false
		repo.CompleteRunFunc = func(ctx context.Context, id int64, status repository.BackupRunStatus, outputPath string, sizeBytes int64, filesBackedUp int, errorMessage string) error {
			called = true
			return nil
		}
		_ = repo.CompleteRun(ctx, 1, repository.BackupRunStatusCompleted, "", 0, 0, "")
		if !called {
			t.Error("should use custom function")
		}
		repo.CompleteRunFunc = nil
	})

	t.Run("ListRunsFunc", func(t *testing.T) {
		repo.ListRunsFunc = func(ctx context.Context, filter repository.BackupRunFilter) ([]repository.BackupRun, error) {
			return []repository.BackupRun{{ID: 1}}, nil
		}
		result, _ := repo.ListRuns(ctx, repository.BackupRunFilter{})
		if len(result) != 1 {
			t.Error("should use custom function")
		}
		repo.ListRunsFunc = nil
	})

	t.Run("GetLastRunForScheduleFunc", func(t *testing.T) {
		repo.GetLastRunForScheduleFunc = func(ctx context.Context, scheduleID int64) (*repository.BackupRun, error) {
			return &repository.BackupRun{ID: 888}, nil
		}
		result, _ := repo.GetLastRunForSchedule(ctx, 1)
		if result.ID != 888 {
			t.Error("should use custom function")
		}
		repo.GetLastRunForScheduleFunc = nil
	})

	t.Run("DeleteOldRunsFunc", func(t *testing.T) {
		repo.DeleteOldRunsFunc = func(ctx context.Context, olderThan time.Time) (int64, error) {
			return 42, nil
		}
		result, _ := repo.DeleteOldRuns(ctx, time.Now())
		if result != 42 {
			t.Error("should use custom function")
		}
		repo.DeleteOldRunsFunc = nil
	})

	t.Run("GetRunStatsFunc", func(t *testing.T) {
		repo.GetRunStatsFunc = func(ctx context.Context) (*repository.BackupRunStats, error) {
			return &repository.BackupRunStats{TotalRuns: 100}, nil
		}
		result, _ := repo.GetRunStats(ctx)
		if result.TotalRuns != 100 {
			t.Error("should use custom function")
		}
		repo.GetRunStatsFunc = nil
	})

	t.Run("GetRunningBackupFunc", func(t *testing.T) {
		repo.GetRunningBackupFunc = func(ctx context.Context) (*repository.BackupRun, error) {
			return &repository.BackupRun{ID: 777}, nil
		}
		result, _ := repo.GetRunningBackup(ctx)
		if result.ID != 777 {
			t.Error("should use custom function")
		}
		repo.GetRunningBackupFunc = nil
	})
}
