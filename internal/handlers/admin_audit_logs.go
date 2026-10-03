package handlers

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// recordAdmin writes an audit entry for an action taken by whoever passed
// AdminAuth on this request.
func recordAdmin(r *http.Request, cfg *config.Config, ev audit.Event) {
	if ev.Type == "" {
		ev.Type = models.AuditEventAdmin
	}
	if actor, ok := middleware.GetAdminActor(r); ok {
		if actor.BuiltIn {
			ev.Username = cfg.AdminUsername
		} else {
			ev.UserID, ev.Username = actor.UserID, actor.Username
		}
	}
	audit.Record(r, cfg, ev)
}

// maxAuditExport caps one export, so a single request can't tie up the
// database indefinitely.
var maxAuditExport = 100000 // a variable so tests can lower it

// parseAuditFilter reads the list/export filters from the query string.
// Dates may be RFC 3339 or YYYY-MM-DD; until is exclusive.
func parseAuditFilter(r *http.Request) (models.AuditLogFilter, error) {
	q := r.URL.Query()
	f := models.AuditLogFilter{
		EventType:    models.AuditEventType(q.Get("event_type")),
		Outcome:      models.AuditOutcome(q.Get("outcome")),
		Action:       q.Get("action"),
		Username:     q.Get("username"),
		IPAddress:    q.Get("ip"),
		ResourceType: q.Get("resource_type"),
		ResourceID:   q.Get("resource_id"),
		Search:       q.Get("search"),
	}
	for _, p := range []struct {
		name string
		dst  *string
	}{{"since", &f.Since}, {"until", &f.Until}} {
		name, dst := p.name, p.dst
		v := q.Get(name)
		if v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			if t, err = time.Parse("2006-01-02", v); err != nil {
				return f, fmt.Errorf("%s must be a date (YYYY-MM-DD) or RFC 3339 time", name)
			}
		}
		*dst = t.UTC().Format(audit.TimestampFormat)
	}
	if v := q.Get("before_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id < 0 {
			return f, fmt.Errorf("before_id must be a positive integer")
		}
		f.BeforeID = id
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return f, fmt.Errorf("limit must be a positive integer")
		}
		f.Limit = n
	}
	return f, nil
}

// AdminAuditLogsHandler lists audit log entries, newest first.
// GET /admin/api/audit-logs - filters as in parseAuditFilter; page with
// before_id = the previous page's next_before_id.
func AdminAuditLogsHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}
		f, err := parseAuditFilter(r)
		if err != nil {
			sendError(w, err.Error(), "INVALID_FILTER", http.StatusBadRequest)
			return
		}
		entries, err := repos.AuditLogs.List(r.Context(), f)
		if err != nil {
			slog.Error("failed to list audit log", "error", err)
			sendError(w, "Failed to load audit log", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []models.AuditLog{}
		}
		resp := map[string]any{"entries": entries}
		if len(entries) > 0 && len(entries) == clampLimit(f.Limit) {
			resp["next_before_id"] = entries[len(entries)-1].ID
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func clampLimit(limit int) int {
	switch {
	case limit <= 0:
		return 50
	case limit > 1000:
		return 1000
	}
	return limit
}

// AdminAuditLogsVerifyHandler checks the whole chain.
// POST /admin/api/audit-logs/verify
func AdminAuditLogsVerifyHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}
		l := audit.Default()
		if l == nil {
			sendError(w, "Audit log is not enabled", "FEATURE_DISABLED", http.StatusServiceUnavailable)
			return
		}
		start := time.Now()
		v, err := l.Verify(r.Context())
		if errors.Is(err, audit.ErrVerifyInProgress) {
			sendError(w, "A verification is already running; try again when it finishes", "VERIFY_IN_PROGRESS", http.StatusConflict)
			return
		}
		if err != nil {
			slog.Error("failed to verify audit log", "error", err)
			sendError(w, "Failed to verify audit log", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		outcome := models.AuditOutcomeSuccess
		if !v.Valid {
			outcome = models.AuditOutcomeFailure
			slog.Warn("audit log verification failed", "problem", v.Problem, "problem_id", v.ProblemID)
		}
		recordAdmin(r, cfg, audit.Event{Type: models.AuditEventSecurity, Action: "audit_log_verify", Outcome: outcome,
			Details: map[string]any{"checked": v.Checked, "last_id": v.LastID, "problem": v.Problem}})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verification": v,
			"key_id":       l.KeyID(),
			"duration_ms":  time.Since(start).Milliseconds(),
		})
	}
}

// AdminAuditLogsExportHandler downloads matching entries, newest first,
// with their hashes, as CSV or JSON Lines.
// GET /admin/api/audit-logs/export?format=csv|jsonl&<filters>
func AdminAuditLogsExportHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}
		f, err := parseAuditFilter(r)
		if err != nil {
			sendError(w, err.Error(), "INVALID_FILTER", http.StatusBadRequest)
			return
		}
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "csv"
		}
		if format != "csv" && format != "jsonl" {
			sendError(w, "format must be csv or jsonl", "INVALID_FORMAT", http.StatusBadRequest)
			return
		}

		recordAdmin(r, cfg, audit.Event{Type: models.AuditEventSecurity, Action: "audit_log_export", Outcome: models.AuditOutcomeSuccess,
			Details: map[string]any{"format": format, "query": r.URL.RawQuery}})

		name := "safeshare-audit-" + time.Now().UTC().Format("20060102-150405") + "." + format
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/x-ndjson")
		}

		var cw *csv.Writer
		enc := json.NewEncoder(w)
		if format == "csv" {
			cw = csv.NewWriter(w)
			_ = cw.Write([]string{"id", "timestamp", "event_type", "action", "outcome", "user_id", "username", "ip_address",
				"user_agent", "resource_type", "resource_id", "details", "prev_hash", "entry_hash", "key_id"})
		}
		written := 0
		complete := false
		for written < maxAuditExport {
			f.Limit = min(1000, maxAuditExport-written)
			entries, err := repos.AuditLogs.List(r.Context(), f)
			if err != nil {
				slog.Error("audit log export failed", "error", err, "written", written)
				break
			}
			for _, e := range entries {
				if cw != nil {
					_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.Timestamp, string(e.EventType), csvSafe(e.Action), string(e.Outcome),
						e.UserID, csvSafe(e.Username), csvSafe(e.IPAddress), csvSafe(e.UserAgent), csvSafe(e.ResourceType), csvSafe(e.ResourceID),
						e.Details, e.PrevHash, e.EntryHash, e.KeyID})
				} else {
					_ = enc.Encode(e)
				}
			}
			written += len(entries)
			if len(entries) < f.Limit {
				complete = true
				break
			}
			f.BeforeID = entries[len(entries)-1].ID
		}
		// Headers are long gone by now, so an export cut short (the cap,
		// or a database error) says so in its last line instead.
		if !complete {
			if cw != nil {
				_ = cw.Write([]string{"# export incomplete: stopped after " + strconv.Itoa(written) + " entries; narrow the filters"})
			} else {
				_ = enc.Encode(map[string]any{"export_incomplete": true, "entries_written": written})
			}
		}
		if cw != nil {
			cw.Flush()
		}
	}
}

// csvSafe stops a spreadsheet from treating client-controlled text as a
// formula (CSV injection). It changes the text, so the CSV can't be used to
// recompute entry hashes; the JSON Lines export is the exact copy. Details
// (always a JSON object) is never affected.
func csvSafe(s string) string {
	if s != "" && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@' || s[0] == '\t' || s[0] == '\r') {
		return "'" + s
	}
	return s
}

// AdminAuditLogsRetentionHandler reads or changes how long entries are kept.
// GET/PUT /admin/api/audit-logs/retention {"retention_days": N} (0 = forever)
func AdminAuditLogsRetentionHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
		case http.MethodPut:
			r.Body = http.MaxBytesReader(w, r.Body, 1024)
			var req struct {
				RetentionDays *int `json:"retention_days"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RetentionDays == nil {
				sendError(w, "retention_days is required", "INVALID_REQUEST", http.StatusBadRequest)
				return
			}
			// At least 30 days: a short retention would let whoever can
			// change it make recent history disappear at the next prune.
			if !audit.ValidRetentionDays(*req.RetentionDays) {
				sendError(w, fmt.Sprintf("retention_days must be 0 (keep forever) or between %d and %d",
					audit.MinRetentionDays, audit.MaxRetentionDays), "INVALID_REQUEST", http.StatusBadRequest)
				return
			}
			old, err := repos.AuditLogs.RetentionDays(r.Context())
			if err != nil {
				slog.Error("failed to read audit log retention", "error", err)
				sendError(w, "Failed to update retention", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			if err := repos.AuditLogs.SetRetentionDays(r.Context(), *req.RetentionDays); err != nil {
				slog.Error("failed to set audit log retention", "error", err)
				sendError(w, "Failed to update retention", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
			recordAdmin(r, cfg, audit.Event{Type: models.AuditEventConfig, Action: "audit_log_retention_update",
				Outcome: models.AuditOutcomeSuccess, Details: map[string]any{"old_days": old, "new_days": *req.RetentionDays}})
		default:
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}
		days, err := repos.AuditLogs.RetentionDays(r.Context())
		if err != nil {
			slog.Error("failed to read audit log retention", "error", err)
			sendError(w, "Failed to read retention", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		resp := map[string]any{"retention_days": days, "enabled": audit.Default() != nil}
		if l := audit.Default(); l != nil {
			if msg, at := l.LastPruneError(); msg != "" {
				resp["last_prune_error"], resp["last_prune_error_at"] = msg, at
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
