package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fjmerc/safeshare/internal/backup"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

// BackupSchedulerHandler provides HTTP handlers for backup scheduler management.
type BackupSchedulerHandler struct {
	repos     *repository.Repositories
	cfg       *config.Config
	scheduler *backup.Scheduler
}

// NewBackupSchedulerHandler creates a new backup scheduler handler.
func NewBackupSchedulerHandler(repos *repository.Repositories, cfg *config.Config, scheduler *backup.Scheduler) *BackupSchedulerHandler {
	return &BackupSchedulerHandler{
		repos:     repos,
		cfg:       cfg,
		scheduler: scheduler,
	}
}

// ListSchedules returns all backup schedules.
// GET /admin/api/backup-schedules
func (h *BackupSchedulerHandler) ListSchedules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		schedules, err := h.repos.BackupScheduler.ListSchedules(ctx)
		if err != nil {
			slog.Error("failed to list backup schedules", "error", err)
			writeJSONError(w, "Failed to list backup schedules", http.StatusInternalServerError)
			return
		}

		// Never return nil slice
		if schedules == nil {
			schedules = []repository.BackupSchedule{}
		}

		writeJSON(w, map[string]interface{}{
			"schedules": schedules,
		}, http.StatusOK)
	}
}

// GetSchedule returns a specific backup schedule.
// GET /admin/api/backup-schedules/{id}
func (h *BackupSchedulerHandler) GetSchedule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse schedule ID from URL
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Schedule ID required", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			writeJSONError(w, "Invalid schedule ID", http.StatusBadRequest)
			return
		}

		schedule, err := h.repos.BackupScheduler.GetSchedule(ctx, id)
		if err != nil {
			if err == repository.ErrNotFound {
				writeJSONError(w, "Schedule not found", http.StatusNotFound)
				return
			}
			slog.Error("failed to get backup schedule", "id", id, "error", err)
			writeJSONError(w, "Failed to get backup schedule", http.StatusInternalServerError)
			return
		}

		writeJSON(w, schedule, http.StatusOK)
	}
}

// UpdateSchedule updates a backup schedule.
// PUT /admin/api/backup-schedules/{id}
func (h *BackupSchedulerHandler) UpdateSchedule() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse schedule ID from URL
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Schedule ID required", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			writeJSONError(w, "Invalid schedule ID", http.StatusBadRequest)
			return
		}

		// Parse request body
		var req struct {
			Name          string `json:"name"`
			Enabled       *bool  `json:"enabled"`
			Schedule      string `json:"schedule"`
			Mode          string `json:"mode"`
			RetentionDays *int   `json:"retention_days"`
		}

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Get existing schedule
		schedule, err := h.repos.BackupScheduler.GetSchedule(ctx, id)
		if err != nil {
			if err == repository.ErrNotFound {
				writeJSONError(w, "Schedule not found", http.StatusNotFound)
				return
			}
			slog.Error("failed to get backup schedule", "id", id, "error", err)
			writeJSONError(w, "Failed to get backup schedule", http.StatusInternalServerError)
			return
		}

		// Update fields if provided
		if req.Name != "" {
			schedule.Name = req.Name
		}
		if req.Enabled != nil {
			schedule.Enabled = *req.Enabled
		}
		if req.Schedule != "" {
			// Validate cron expression before updating
			if err := backup.ValidateCronExpression(req.Schedule); err != nil {
				writeJSONError(w, "Invalid cron expression: "+err.Error(), http.StatusBadRequest)
				return
			}
			schedule.Schedule = req.Schedule
		}
		if req.Mode != "" {
			// Validate mode
			validModes := map[string]bool{"full": true, "database": true, "config": true}
			if !validModes[req.Mode] {
				writeJSONError(w, "Invalid backup mode", http.StatusBadRequest)
				return
			}
			schedule.Mode = req.Mode
		}
		if req.RetentionDays != nil {
			if *req.RetentionDays < 0 {
				writeJSONError(w, "Retention days must be 0 or positive", http.StatusBadRequest)
				return
			}
			schedule.RetentionDays = *req.RetentionDays
		}

		// Update the schedule
		if err := h.repos.BackupScheduler.UpdateSchedule(ctx, schedule); err != nil {
			slog.Error("failed to update backup schedule", "id", id, "error", err)
			writeJSONError(w, "Failed to update backup schedule", http.StatusInternalServerError)
			return
		}

		slog.Info("backup schedule updated",
			"schedule_id", schedule.ID,
			"schedule_name", schedule.Name,
			"enabled", schedule.Enabled)

		writeJSON(w, schedule, http.StatusOK)
	}
}

// ListRuns returns backup run history.
// GET /admin/api/backup-runs
// Query params: schedule_id, status, trigger_type, limit, offset
func (h *BackupSchedulerHandler) ListRuns() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse query parameters
		filter := repository.BackupRunFilter{
			Limit:  100,
			Offset: 0,
		}

		if scheduleIDStr := r.URL.Query().Get("schedule_id"); scheduleIDStr != "" {
			if scheduleID, err := strconv.ParseInt(scheduleIDStr, 10, 64); err == nil && scheduleID > 0 {
				filter.ScheduleID = &scheduleID
			}
		}

		if statusStr := r.URL.Query().Get("status"); statusStr != "" {
			status := repository.BackupRunStatus(statusStr)
			filter.Status = &status
		}

		if triggerStr := r.URL.Query().Get("trigger_type"); triggerStr != "" {
			trigger := repository.BackupTriggerType(triggerStr)
			filter.TriggerType = &trigger
		}

		if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
			if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 1000 {
				filter.Limit = limit
			}
		}

		if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
			if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
				filter.Offset = offset
			}
		}

		runs, err := h.repos.BackupScheduler.ListRuns(ctx, filter)
		if err != nil {
			slog.Error("failed to list backup runs", "error", err)
			writeJSONError(w, "Failed to list backup runs", http.StatusInternalServerError)
			return
		}

		// Never return nil slice
		if runs == nil {
			runs = []repository.BackupRun{}
		}

		writeJSON(w, map[string]interface{}{
			"runs":   runs,
			"limit":  filter.Limit,
			"offset": filter.Offset,
		}, http.StatusOK)
	}
}

// GetRun returns a specific backup run.
// GET /admin/api/backup-runs/{id}
func (h *BackupSchedulerHandler) GetRun() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse run ID from URL
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Run ID required", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			writeJSONError(w, "Invalid run ID", http.StatusBadRequest)
			return
		}

		run, err := h.repos.BackupScheduler.GetRun(ctx, id)
		if err != nil {
			if err == repository.ErrNotFound {
				writeJSONError(w, "Run not found", http.StatusNotFound)
				return
			}
			slog.Error("failed to get backup run", "id", id, "error", err)
			writeJSONError(w, "Failed to get backup run", http.StatusInternalServerError)
			return
		}

		writeJSON(w, run, http.StatusOK)
	}
}

// GetStats returns backup run statistics.
// GET /admin/api/backup-stats
func (h *BackupSchedulerHandler) GetStats() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		stats, err := h.repos.BackupScheduler.GetRunStats(ctx)
		if err != nil {
			slog.Error("failed to get backup stats", "error", err)
			writeJSONError(w, "Failed to get backup stats", http.StatusInternalServerError)
			return
		}

		// Add scheduler status
		response := map[string]interface{}{
			"stats":             stats,
			"scheduler_running": h.scheduler != nil && h.scheduler.IsRunning(),
		}

		writeJSON(w, response, http.StatusOK)
	}
}

// TriggerBackup triggers a manual backup.
// POST /admin/api/backup-trigger
func (h *BackupSchedulerHandler) TriggerBackup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse request body
		var req struct {
			Mode string `json:"mode"`
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Default to full backup
		if req.Mode == "" {
			req.Mode = "full"
		}

		// Validate mode
		validModes := map[string]bool{"full": true, "database": true, "config": true}
		if !validModes[req.Mode] {
			writeJSONError(w, "Invalid backup mode. Must be 'full', 'database', or 'config'", http.StatusBadRequest)
			return
		}

		// Check if scheduler is available
		if h.scheduler == nil {
			writeJSONError(w, "Backup scheduler not available", http.StatusServiceUnavailable)
			return
		}

		// Trigger the backup
		run, err := h.scheduler.TriggerBackup(ctx, req.Mode, repository.BackupTriggerAPI)
		if err != nil {
			// Use appropriate status code based on error type
			statusCode := http.StatusInternalServerError
			if errors.Is(err, backup.ErrBackupAlreadyRunning) {
				statusCode = http.StatusConflict
			}
			slog.Error("failed to trigger backup", "mode", req.Mode, "error", err)
			writeJSONError(w, "Failed to start backup: a backup may already be running", statusCode)
			return
		}

		slog.Info("manual backup triggered",
			"run_id", run.ID,
			"mode", req.Mode,
			"trigger_type", "api")

		writeJSON(w, map[string]interface{}{
			"message": "Backup started",
			"run":     run,
		}, http.StatusAccepted)
	}
}

// GetRunningBackup returns the currently running backup, if any.
// GET /admin/api/backup-running
func (h *BackupSchedulerHandler) GetRunningBackup() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		run, err := h.repos.BackupScheduler.GetRunningBackup(ctx)
		if err != nil {
			slog.Error("failed to get running backup", "error", err)
			writeJSONError(w, "Failed to get running backup", http.StatusInternalServerError)
			return
		}

		if run == nil {
			writeJSON(w, map[string]interface{}{
				"running": false,
			}, http.StatusOK)
			return
		}

		// Calculate progress estimate based on elapsed time
		elapsedMs := time.Since(run.StartedAt).Milliseconds()
		progress := 0
		if elapsedMs > 0 {
			// Estimate based on typical backup duration (5 minutes average)
			progress = int(float64(elapsedMs) / float64(5*60*1000) * 100)
			if progress > 99 {
				progress = 99 // Never show 100% until actually complete
			}
		}

		writeJSON(w, map[string]interface{}{
			"running":    true,
			"run":        run,
			"elapsed_ms": elapsedMs,
			"progress":   progress,
		}, http.StatusOK)
	}
}

// Helper functions

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	writeJSON(w, map[string]string{"error": message}, statusCode)
}
