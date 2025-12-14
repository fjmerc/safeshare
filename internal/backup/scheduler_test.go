package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/mock"
)

// ============================================================================
// Cron Expression Validation Tests
// ============================================================================

func TestValidateCronExpression(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{
			name:    "valid daily at 2am",
			expr:    "0 2 * * *",
			wantErr: false,
		},
		{
			name:    "valid midnight sunday",
			expr:    "0 0 * * 0",
			wantErr: false,
		},
		{
			name:    "valid every hour",
			expr:    "0 * * * *",
			wantErr: false,
		},
		{
			name:    "valid specific day of month",
			expr:    "30 3 15 * *",
			wantErr: false,
		},
		{
			name:    "valid specific month",
			expr:    "0 12 1 6 *",
			wantErr: false,
		},
		{
			name:    "all wildcards",
			expr:    "* * * * *",
			wantErr: false,
		},
		{
			name:    "too few fields",
			expr:    "0 2 * *",
			wantErr: true,
		},
		{
			name:    "too many fields",
			expr:    "0 2 * * * *",
			wantErr: true,
		},
		{
			name:    "empty expression",
			expr:    "",
			wantErr: true,
		},
		{
			name:    "invalid minute too high",
			expr:    "60 2 * * *",
			wantErr: true,
		},
		{
			name:    "invalid hour too high",
			expr:    "0 24 * * *",
			wantErr: true,
		},
		{
			name:    "invalid day of month zero",
			expr:    "0 0 0 * *",
			wantErr: true,
		},
		{
			name:    "invalid day of month too high",
			expr:    "0 0 32 * *",
			wantErr: true,
		},
		{
			name:    "invalid month zero",
			expr:    "0 0 * 0 *",
			wantErr: true,
		},
		{
			name:    "invalid month too high",
			expr:    "0 0 * 13 *",
			wantErr: true,
		},
		{
			name:    "invalid day of week too high",
			expr:    "0 0 * * 7",
			wantErr: true,
		},
		{
			name:    "invalid format - letters",
			expr:    "a b * * *",
			wantErr: true,
		},
		{
			name:    "negative minute",
			expr:    "-1 0 * * *",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCronExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCronExpression(%q) error = %v, wantErr %v", tt.expr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCronField(t *testing.T) {
	tests := []struct {
		name      string
		field     string
		minVal    int
		maxVal    int
		fieldName string
		wantErr   bool
	}{
		{
			name:      "wildcard",
			field:     "*",
			minVal:    0,
			maxVal:    59,
			fieldName: "minute",
			wantErr:   false,
		},
		{
			name:      "valid number in range",
			field:     "30",
			minVal:    0,
			maxVal:    59,
			fieldName: "minute",
			wantErr:   false,
		},
		{
			name:      "valid at min boundary",
			field:     "0",
			minVal:    0,
			maxVal:    59,
			fieldName: "minute",
			wantErr:   false,
		},
		{
			name:      "valid at max boundary",
			field:     "59",
			minVal:    0,
			maxVal:    59,
			fieldName: "minute",
			wantErr:   false,
		},
		{
			name:      "below min",
			field:     "0",
			minVal:    1,
			maxVal:    31,
			fieldName: "day",
			wantErr:   true,
		},
		{
			name:      "above max",
			field:     "60",
			minVal:    0,
			maxVal:    59,
			fieldName: "minute",
			wantErr:   true,
		},
		{
			name:      "invalid characters",
			field:     "abc",
			minVal:    0,
			maxVal:    59,
			fieldName: "minute",
			wantErr:   true,
		},
		{
			name:      "mixed characters",
			field:     "1a",
			minVal:    0,
			maxVal:    59,
			fieldName: "minute",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCronField(tt.field, tt.minVal, tt.maxVal, tt.fieldName)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCronField(%q, %d, %d, %q) error = %v, wantErr %v",
					tt.field, tt.minVal, tt.maxVal, tt.fieldName, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// Sanitize Error Message Tests
// ============================================================================

func TestSanitizeErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		excludes string
	}{
		{
			name:     "simple path",
			input:    "failed to read /home/user/data/file.txt",
			contains: "[.../file.txt]",
			excludes: "/home/user",
		},
		{
			name:     "multiple paths",
			input:    "error copying /var/log/app.log to /tmp/backup/app.log",
			contains: "[.../app.log]",
			excludes: "/var/log",
		},
		{
			name:     "no path",
			input:    "connection timeout",
			contains: "connection timeout",
			excludes: "",
		},
		{
			name:     "empty message",
			input:    "",
			contains: "",
			excludes: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeErrorMessage(tt.input)

			if tt.contains != "" && !stringContains(result, tt.contains) {
				t.Errorf("sanitizeErrorMessage(%q) = %q, expected to contain %q", tt.input, result, tt.contains)
			}

			if tt.excludes != "" && stringContains(result, tt.excludes) {
				t.Errorf("sanitizeErrorMessage(%q) = %q, expected to NOT contain %q", tt.input, result, tt.excludes)
			}
		})
	}
}

// Helper function for string contains
func stringContains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ============================================================================
// Scheduler Creation Tests
// ============================================================================

func TestNewScheduler(t *testing.T) {
	cfg := &config.Config{
		DataDir: "/tmp/data",
	}
	repos := &repository.Repositories{}

	scheduler := NewScheduler(cfg, repos)

	if scheduler == nil {
		t.Fatal("NewScheduler returned nil")
	}

	if scheduler.cfg != cfg {
		t.Error("scheduler config not set correctly")
	}

	if scheduler.repos != repos {
		t.Error("scheduler repos not set correctly")
	}

	if scheduler.checkInterval != time.Minute {
		t.Errorf("checkInterval = %v, want %v", scheduler.checkInterval, time.Minute)
	}

	if scheduler.running.Load() {
		t.Error("scheduler should not be running initially")
	}
}

func TestSchedulerIsRunning(t *testing.T) {
	scheduler := &Scheduler{}

	if scheduler.IsRunning() {
		t.Error("new scheduler should not be running")
	}

	scheduler.running.Store(true)

	if !scheduler.IsRunning() {
		t.Error("scheduler should be running after setting flag")
	}

	scheduler.running.Store(false)

	if scheduler.IsRunning() {
		t.Error("scheduler should not be running after clearing flag")
	}
}

// ============================================================================
// Calculate Next Run Tests
// ============================================================================

func TestCalculateNextRun(t *testing.T) {
	scheduler := &Scheduler{}

	tests := []struct {
		name     string
		cronExpr string
		from     time.Time
		wantHour int
		wantMin  int
	}{
		{
			name:     "daily at 2am from morning",
			cronExpr: "0 2 * * *",
			from:     time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
			wantHour: 2,
			wantMin:  0,
		},
		{
			name:     "daily at 2am from 1am (same day)",
			cronExpr: "0 2 * * *",
			from:     time.Date(2024, 1, 15, 1, 0, 0, 0, time.UTC),
			wantHour: 2,
			wantMin:  0,
		},
		{
			name:     "specific minute",
			cronExpr: "30 14 * * *",
			from:     time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
			wantHour: 14,
			wantMin:  30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scheduler.calculateNextRun(tt.cronExpr, tt.from)

			if result == nil {
				t.Fatal("calculateNextRun returned nil")
			}

			if result.Hour() != tt.wantHour {
				t.Errorf("hour = %d, want %d", result.Hour(), tt.wantHour)
			}

			if result.Minute() != tt.wantMin {
				t.Errorf("minute = %d, want %d", result.Minute(), tt.wantMin)
			}

			if !result.After(tt.from) {
				t.Error("next run should be after 'from' time")
			}
		})
	}
}

func TestCalculateNextRunWithDayOfWeek(t *testing.T) {
	scheduler := &Scheduler{}

	// Sunday = 0
	// Find next Sunday at midnight from a Wednesday
	cronExpr := "0 0 * * 0"
	from := time.Date(2024, 1, 17, 10, 0, 0, 0, time.UTC) // Wednesday

	result := scheduler.calculateNextRun(cronExpr, from)

	if result == nil {
		t.Fatal("calculateNextRun returned nil")
	}

	if result.Weekday() != time.Sunday {
		t.Errorf("weekday = %v, want Sunday", result.Weekday())
	}

	if result.Hour() != 0 || result.Minute() != 0 {
		t.Errorf("time = %02d:%02d, want 00:00", result.Hour(), result.Minute())
	}
}

func TestCalculateNextRunInvalidCron(t *testing.T) {
	scheduler := &Scheduler{}

	// Invalid cron expression should fall back to default (next day at 2 AM)
	tests := []struct {
		name     string
		cronExpr string
	}{
		{"too few fields", "0 2 *"},
		{"empty", ""},
		{"invalid minute", "abc 2 * * *"},
		{"invalid hour", "0 abc * * *"},
	}

	from := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scheduler.calculateNextRun(tt.cronExpr, from)

			if result == nil {
				t.Fatal("calculateNextRun returned nil")
			}

			// Should default to 2 AM next day
			expectedDay := from.Day() + 1
			if result.Day() != expectedDay && result.Month() == from.Month() {
				// Allow for month rollover
				if result.Month() != from.Month()+1 || result.Day() != 1 {
					t.Errorf("day = %d, expected next day or month rollover", result.Day())
				}
			}

			if result.Hour() != 2 {
				t.Errorf("hour = %d, want 2 (default fallback)", result.Hour())
			}
		})
	}
}

// ============================================================================
// Backup Directory Regex Tests
// ============================================================================

func TestBackupDirNameRegex(t *testing.T) {
	tests := []struct {
		name    string
		dirName string
		match   bool
	}{
		{"valid format", "backup-20240115-143022", true},
		{"valid format 2", "backup-19991231-235959", true},
		{"missing prefix", "20240115-143022", false},
		{"wrong prefix", "bkp-20240115-143022", false},
		{"extra suffix", "backup-20240115-143022-extra", false},
		{"short date", "backup-2024015-143022", false},
		{"short time", "backup-20240115-14302", false},
		{"letters in date", "backup-2024011a-143022", false},
		{"empty", "", false},
		{"just prefix", "backup-", false},
		{"path traversal attempt", "../backup-20240115-143022", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := backupDirNameRegex.MatchString(tt.dirName)
			if match != tt.match {
				t.Errorf("backupDirNameRegex.MatchString(%q) = %v, want %v", tt.dirName, match, tt.match)
			}
		})
	}
}

// ============================================================================
// Cleanup Old Backup Directories Tests
// ============================================================================

func TestCleanupOldBackupDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		BackupDir: tmpDir,
	}
	scheduler := &Scheduler{cfg: cfg}

	// Create some backup directories with different ages
	oldBackup := filepath.Join(tmpDir, "backup-20230101-120000")
	newBackup := filepath.Join(tmpDir, "backup-20240115-120000")
	nonBackup := filepath.Join(tmpDir, "other-directory")

	if err := os.MkdirAll(oldBackup, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(newBackup, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(nonBackup, 0755); err != nil {
		t.Fatal(err)
	}

	// Set old modification time on old backup
	oldTime := time.Now().AddDate(0, 0, -60)
	if err := os.Chtimes(oldBackup, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	// Cutoff is 30 days ago
	cutoffTime := time.Now().AddDate(0, 0, -30)

	scheduler.cleanupOldBackupDirectories(cutoffTime)

	// Old backup should be removed
	if _, err := os.Stat(oldBackup); !os.IsNotExist(err) {
		t.Error("old backup directory should have been removed")
	}

	// New backup should still exist
	if _, err := os.Stat(newBackup); err != nil {
		t.Error("new backup directory should still exist")
	}

	// Non-backup directory should still exist (not matching pattern)
	if _, err := os.Stat(nonBackup); err != nil {
		t.Error("non-backup directory should still exist")
	}
}

func TestCleanupOldBackupDirectoriesNonexistent(t *testing.T) {
	cfg := &config.Config{
		BackupDir: "/nonexistent/path",
	}
	scheduler := &Scheduler{cfg: cfg}

	// Should not panic
	scheduler.cleanupOldBackupDirectories(time.Now())
}

// ============================================================================
// Scheduler Start/Stop Tests
// ============================================================================

func TestSchedulerStartAlreadyRunning(t *testing.T) {
	mockBackupScheduler := mock.NewBackupSchedulerRepository()
	repos := &repository.Repositories{
		BackupScheduler: mockBackupScheduler,
	}

	cfg := &config.Config{}
	scheduler := NewScheduler(cfg, repos)

	// Manually set running to true
	scheduler.running.Store(true)

	// Start should return error
	err := scheduler.Start(context.Background())
	if err == nil {
		t.Error("Start should return error when already running")
	}

	if err.Error() != "scheduler already running" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSchedulerStopNotRunning(t *testing.T) {
	scheduler := &Scheduler{}

	// Stop should not panic when not running
	scheduler.Stop()

	// Should still not be running
	if scheduler.IsRunning() {
		t.Error("scheduler should not be running after Stop")
	}
}

// ============================================================================
// Error Variable Tests
// ============================================================================

func TestErrBackupAlreadyRunning(t *testing.T) {
	if ErrBackupAlreadyRunning == nil {
		t.Error("ErrBackupAlreadyRunning should not be nil")
	}

	if ErrBackupAlreadyRunning.Error() != "another backup is already running" {
		t.Errorf("unexpected error message: %v", ErrBackupAlreadyRunning)
	}
}

func TestErrInvalidCronExpression(t *testing.T) {
	if ErrInvalidCronExpression == nil {
		t.Error("ErrInvalidCronExpression should not be nil")
	}

	if ErrInvalidCronExpression.Error() != "invalid cron expression" {
		t.Errorf("unexpected error message: %v", ErrInvalidCronExpression)
	}
}

// ============================================================================
// Integration-style Tests (with mocks)
// ============================================================================

func TestSchedulerStartAndStop(t *testing.T) {
	mockBackupScheduler := mock.NewBackupSchedulerRepository()
	repos := &repository.Repositories{
		BackupScheduler: mockBackupScheduler,
	}

	cfg := &config.Config{
		DataDir: t.TempDir(),
	}
	scheduler := NewScheduler(cfg, repos)

	// Reduce check interval for faster test
	scheduler.checkInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start scheduler
	err := scheduler.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !scheduler.IsRunning() {
		t.Error("scheduler should be running after Start")
	}

	// Give it a moment to run
	time.Sleep(50 * time.Millisecond)

	// Stop scheduler
	scheduler.Stop()

	if scheduler.IsRunning() {
		t.Error("scheduler should not be running after Stop")
	}
}

func TestSchedulerWithAutoBackupConfig(t *testing.T) {
	mockBackupScheduler := mock.NewBackupSchedulerRepository()
	repos := &repository.Repositories{
		BackupScheduler: mockBackupScheduler,
	}

	cfg := &config.Config{
		DataDir: t.TempDir(),
		AutoBackup: &config.AutoBackupConfig{
			Enabled:       true,
			Schedule:      "0 2 * * *",
			Mode:          "database",
			RetentionDays: 7,
		},
	}
	scheduler := NewScheduler(cfg, repos)
	scheduler.checkInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := scheduler.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Give it time to initialize
	time.Sleep(50 * time.Millisecond)

	scheduler.Stop()
}

func TestSchedulerStartContextCancel(t *testing.T) {
	mockBackupScheduler := mock.NewBackupSchedulerRepository()
	repos := &repository.Repositories{
		BackupScheduler: mockBackupScheduler,
	}

	cfg := &config.Config{
		DataDir: t.TempDir(),
	}
	scheduler := NewScheduler(cfg, repos)
	scheduler.checkInterval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	err := scheduler.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Cancel context should cause run loop to exit
	cancel()

	// Give it time to respond to cancellation
	time.Sleep(50 * time.Millisecond)

	// Clean up
	scheduler.Stop()
}

// ============================================================================
// Cron Field Regex Tests
// ============================================================================

func TestCronFieldRegex(t *testing.T) {
	tests := []struct {
		field string
		match bool
	}{
		{"*", true},
		{"0", true},
		{"59", true},
		{"123", true},
		{"abc", false},
		{"1a", false},
		{"", false},
		{"-1", false},
		{"1-5", false}, // Range not supported
		{"*/5", false}, // Step not supported
	}

	for _, tt := range tests {
		match := cronFieldRegex.MatchString(tt.field)
		if match != tt.match {
			t.Errorf("cronFieldRegex.MatchString(%q) = %v, want %v", tt.field, match, tt.match)
		}
	}
}
