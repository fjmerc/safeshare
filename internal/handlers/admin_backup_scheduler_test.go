package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func setupBackupSchedulerTestDB(t *testing.T) (*sql.DB, *repository.Repositories, *config.Config) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("Failed to create repositories: %v", err)
	}

	return db, repos, cfg
}

// clearBackupSchedules removes all backup schedules including the default one from migrations
func clearBackupSchedules(t *testing.T, db *sql.DB) {
	_, err := db.Exec("DELETE FROM backup_schedules")
	if err != nil {
		t.Fatalf("Failed to clear backup schedules: %v", err)
	}
}

// getScheduleCount returns the current number of backup schedules in the database
func getScheduleCount(t *testing.T, db *sql.DB) int {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM backup_schedules").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count schedules: %v", err)
	}
	return count
}

func createTestSchedule(t *testing.T, db *sql.DB) int64 {
	result, err := db.Exec(`
		INSERT INTO backup_schedules (name, enabled, schedule, mode, retention_days)
		VALUES (?, ?, ?, ?, ?)
	`, "Daily Full Backup", true, "0 0 * * *", "full", 7)
	if err != nil {
		t.Fatalf("Failed to create test schedule: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

func createTestBackupRun(t *testing.T, db *sql.DB, scheduleID int64, status string) int64 {
	startedAt := time.Now().Add(-time.Hour)
	completedAt := time.Now()
	result, err := db.Exec(`
		INSERT INTO backup_runs (schedule_id, mode, trigger_type, status, output_path, size_bytes, started_at, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, scheduleID, "full", "scheduled", status, "/backups/test-backup", 1024000, startedAt.Format(time.RFC3339), completedAt.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to create test backup run: %v", err)
	}
	id, _ := result.LastInsertId()
	return id
}

func TestNewBackupSchedulerHandler(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)

	if handler == nil {
		t.Error("Expected non-nil handler")
	}
	if handler.repos != repos {
		t.Error("Expected repos to be set")
	}
	if handler.cfg != cfg {
		t.Error("Expected cfg to be set")
	}
}

func TestBackupSchedulerHandler_ListSchedules_Success(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	// Clear default schedules and create our test schedule
	clearBackupSchedules(t, db)
	createTestSchedule(t, db)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	listHandler := handler.ListSchedules()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-schedules", nil)
	w := httptest.NewRecorder()

	listHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	schedules, ok := response["schedules"].([]interface{})
	if !ok {
		t.Fatal("Expected schedules array in response")
	}
	if len(schedules) != 1 {
		t.Errorf("Expected 1 schedule, got %d", len(schedules))
	}
}

func TestBackupSchedulerHandler_ListSchedules_Empty(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	// Clear all schedules including the default one from migrations
	clearBackupSchedules(t, db)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	listHandler := handler.ListSchedules()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-schedules", nil)
	w := httptest.NewRecorder()

	listHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	schedules, ok := response["schedules"].([]interface{})
	if !ok {
		t.Fatal("Expected schedules array in response")
	}
	if len(schedules) != 0 {
		t.Errorf("Expected empty schedules, got %d", len(schedules))
	}
}

func TestBackupSchedulerHandler_GetSchedule_Success(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	// Clear default schedules and create our test schedule
	clearBackupSchedules(t, db)
	scheduleID := createTestSchedule(t, db)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	getHandler := handler.GetSchedule()

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/backup-schedules/%d", scheduleID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", scheduleID))
	w := httptest.NewRecorder()

	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var schedule repository.BackupSchedule
	if err := json.NewDecoder(w.Body).Decode(&schedule); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if schedule.ID != scheduleID {
		t.Errorf("Expected ID %d, got %d", scheduleID, schedule.ID)
	}
	if schedule.Name != "Daily Full Backup" {
		t.Errorf("Expected name 'Daily Full Backup', got '%s'", schedule.Name)
	}
}

func TestBackupSchedulerHandler_GetSchedule_NotFound(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	getHandler := handler.GetSchedule()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-schedules/99999", nil)
	req.SetPathValue("id", "99999")
	w := httptest.NewRecorder()

	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestBackupSchedulerHandler_GetSchedule_InvalidID(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	getHandler := handler.GetSchedule()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-schedules/invalid", nil)
	req.SetPathValue("id", "invalid")
	w := httptest.NewRecorder()

	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_GetSchedule_MissingID(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	getHandler := handler.GetSchedule()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-schedules/", nil)
	req.SetPathValue("id", "")
	w := httptest.NewRecorder()

	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_UpdateSchedule_Success(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	// Use the default schedule (ID=1) from migrations
	// or create a new one if we need a specific ID
	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		createTestSchedule(t, db)
	}

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	updateHandler := handler.UpdateSchedule()

	enabled := false
	body, _ := json.Marshal(map[string]interface{}{
		"name":    "Updated Backup",
		"enabled": enabled,
	})

	req := httptest.NewRequest(http.MethodPut, "/admin/api/backup-schedules/1", bytes.NewReader(body))
	req.SetPathValue("id", "1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	updateHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var schedule repository.BackupSchedule
	if err := json.NewDecoder(w.Body).Decode(&schedule); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if schedule.Name != "Updated Backup" {
		t.Errorf("Expected name 'Updated Backup', got '%s'", schedule.Name)
	}
	if schedule.Enabled != false {
		t.Error("Expected enabled to be false")
	}
}

func TestBackupSchedulerHandler_UpdateSchedule_InvalidCron(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		createTestSchedule(t, db)
	}

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	updateHandler := handler.UpdateSchedule()

	body, _ := json.Marshal(map[string]interface{}{
		"schedule": "invalid cron expression",
	})

	req := httptest.NewRequest(http.MethodPut, "/admin/api/backup-schedules/1", bytes.NewReader(body))
	req.SetPathValue("id", "1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	updateHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_UpdateSchedule_InvalidMode(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		createTestSchedule(t, db)
	}

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	updateHandler := handler.UpdateSchedule()

	body, _ := json.Marshal(map[string]interface{}{
		"mode": "invalid_mode",
	})

	req := httptest.NewRequest(http.MethodPut, "/admin/api/backup-schedules/1", bytes.NewReader(body))
	req.SetPathValue("id", "1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	updateHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_UpdateSchedule_NegativeRetention(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		createTestSchedule(t, db)
	}

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	updateHandler := handler.UpdateSchedule()

	retentionDays := -1
	body, _ := json.Marshal(map[string]interface{}{
		"retention_days": retentionDays,
	})

	req := httptest.NewRequest(http.MethodPut, "/admin/api/backup-schedules/1", bytes.NewReader(body))
	req.SetPathValue("id", "1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	updateHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_UpdateSchedule_NotFound(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	updateHandler := handler.UpdateSchedule()

	body, _ := json.Marshal(map[string]interface{}{
		"name": "Updated Backup",
	})

	req := httptest.NewRequest(http.MethodPut, "/admin/api/backup-schedules/99999", bytes.NewReader(body))
	req.SetPathValue("id", "99999")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	updateHandler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestBackupSchedulerHandler_UpdateSchedule_InvalidJSON(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		createTestSchedule(t, db)
	}

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	updateHandler := handler.UpdateSchedule()

	req := httptest.NewRequest(http.MethodPut, "/admin/api/backup-schedules/1", bytes.NewReader([]byte("invalid json")))
	req.SetPathValue("id", "1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	updateHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_ListRuns_Success(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	// Use the default schedule ID (1) if it exists
	var scheduleID int64 = 1
	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		scheduleID = createTestSchedule(t, db)
	}
	createTestBackupRun(t, db, scheduleID, "completed")

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	listHandler := handler.ListRuns()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-runs", nil)
	w := httptest.NewRecorder()

	listHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	runs, ok := response["runs"].([]interface{})
	if !ok {
		t.Fatal("Expected runs array in response")
	}
	if len(runs) != 1 {
		t.Errorf("Expected 1 run, got %d", len(runs))
	}
}

func TestBackupSchedulerHandler_ListRuns_WithFilters(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	var scheduleID int64 = 1
	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		scheduleID = createTestSchedule(t, db)
	}
	createTestBackupRun(t, db, scheduleID, "completed")

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	listHandler := handler.ListRuns()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-runs?schedule_id=1&status=completed&trigger_type=scheduled&limit=10&offset=0", nil)
	w := httptest.NewRecorder()

	listHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if int(response["limit"].(float64)) != 10 {
		t.Errorf("Expected limit 10, got %v", response["limit"])
	}
}

func TestBackupSchedulerHandler_ListRuns_Empty(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	listHandler := handler.ListRuns()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-runs", nil)
	w := httptest.NewRecorder()

	listHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	runs, ok := response["runs"].([]interface{})
	if !ok {
		t.Fatal("Expected runs array in response")
	}
	if len(runs) != 0 {
		t.Errorf("Expected empty runs, got %d", len(runs))
	}
}

func TestBackupSchedulerHandler_GetRun_Success(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	var scheduleID int64 = 1
	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		scheduleID = createTestSchedule(t, db)
	}
	runID := createTestBackupRun(t, db, scheduleID, "completed")

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	getHandler := handler.GetRun()

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/api/backup-runs/%d", runID), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", runID))
	w := httptest.NewRecorder()

	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var run repository.BackupRun
	if err := json.NewDecoder(w.Body).Decode(&run); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if run.ID != runID {
		t.Errorf("Expected ID %d, got %d", runID, run.ID)
	}
}

func TestBackupSchedulerHandler_GetRun_NotFound(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	getHandler := handler.GetRun()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-runs/99999", nil)
	req.SetPathValue("id", "99999")
	w := httptest.NewRecorder()

	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestBackupSchedulerHandler_GetRun_InvalidID(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	getHandler := handler.GetRun()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-runs/invalid", nil)
	req.SetPathValue("id", "invalid")
	w := httptest.NewRecorder()

	getHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_GetStats_Success(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	var scheduleID int64 = 1
	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		scheduleID = createTestSchedule(t, db)
	}
	createTestBackupRun(t, db, scheduleID, "completed")

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	statsHandler := handler.GetStats()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-stats", nil)
	w := httptest.NewRecorder()

	statsHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if _, ok := response["stats"]; !ok {
		t.Error("Expected stats in response")
	}
	if _, ok := response["scheduler_running"]; !ok {
		t.Error("Expected scheduler_running in response")
	}
}

func TestBackupSchedulerHandler_TriggerBackup_NoScheduler(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	// Create handler without scheduler
	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	triggerHandler := handler.TriggerBackup()

	body, _ := json.Marshal(map[string]string{"mode": "full"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/backup-trigger", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	triggerHandler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestBackupSchedulerHandler_TriggerBackup_InvalidMode(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	triggerHandler := handler.TriggerBackup()

	body, _ := json.Marshal(map[string]string{"mode": "invalid_mode"})
	req := httptest.NewRequest(http.MethodPost, "/admin/api/backup-trigger", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	triggerHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_TriggerBackup_InvalidJSON(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	triggerHandler := handler.TriggerBackup()

	req := httptest.NewRequest(http.MethodPost, "/admin/api/backup-trigger", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	triggerHandler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBackupSchedulerHandler_GetRunningBackup_NoRunning(t *testing.T) {
	_, repos, cfg := setupBackupSchedulerTestDB(t)

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	runningHandler := handler.GetRunningBackup()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-running", nil)
	w := httptest.NewRecorder()

	runningHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["running"] != false {
		t.Error("Expected running to be false")
	}
}

func TestBackupSchedulerHandler_GetRunningBackup_WithRunning(t *testing.T) {
	db, repos, cfg := setupBackupSchedulerTestDB(t)

	var scheduleID int64 = 1
	initialCount := getScheduleCount(t, db)
	if initialCount == 0 {
		scheduleID = createTestSchedule(t, db)
	}

	// Create a running backup
	startedAt := time.Now().Add(-time.Minute)
	_, err := db.Exec(`
		INSERT INTO backup_runs (schedule_id, mode, trigger_type, status, started_at)
		VALUES (?, ?, ?, ?, ?)
	`, scheduleID, "full", "api", "running", startedAt.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("Failed to create running backup: %v", err)
	}

	handler := NewBackupSchedulerHandler(repos, cfg, nil)
	runningHandler := handler.GetRunningBackup()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/backup-running", nil)
	w := httptest.NewRecorder()

	runningHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["running"] != true {
		t.Error("Expected running to be true")
	}
	if _, ok := response["run"]; !ok {
		t.Error("Expected run in response")
	}
	if _, ok := response["progress"]; !ok {
		t.Error("Expected progress in response")
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()

	data := map[string]string{"test": "value"}
	writeJSON(w, data, http.StatusCreated)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("Expected Content-Type application/json")
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["test"] != "value" {
		t.Errorf("Expected 'value', got '%s'", response["test"])
	}
}

func TestWriteJSONError(t *testing.T) {
	w := httptest.NewRecorder()

	writeJSONError(w, "Test error message", http.StatusBadRequest)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["error"] != "Test error message" {
		t.Errorf("Expected 'Test error message', got '%s'", response["error"])
	}
}
