package audit

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

// writeFailures counts audit entries that could not be written.
var writeFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "safeshare_audit_log_write_failures_total",
	Help: "Audit log entries that could not be written",
})

var defaultLogger atomic.Pointer[Logger]

// SetDefault sets the logger Record writes to. Until it's called (and in
// tests that don't), Record does nothing.
func SetDefault(l *Logger) { defaultLogger.Store(l) }

// Default returns the logger Record writes to, or nil.
func Default() *Logger { return defaultLogger.Load() }

// Event describes something that happened during a request.
type Event struct {
	Type         models.AuditEventType
	Action       string
	Outcome      models.AuditOutcome
	UserID       int64  // the acting account, 0 for none
	Username     string // the acting (or, for a failed login, attempted) username
	ResourceType string
	ResourceID   string
	Details      map[string]any
}

// Record writes ev to the audit log, filling in who made the request. In
// anonymous mode it stores nothing that identifies them: no address,
// account, username or user agent.
//
// It returns once the entry is durable. If it can't be written, that is
// logged and counted but the request carries on: an audit log that can't
// keep up must not lock everyone out of logging in.
func Record(r *http.Request, cfg *config.Config, ev Event) {
	l := Default()
	if l == nil {
		return
	}
	in := Entry{
		Type:         ev.Type,
		Action:       ev.Action,
		Outcome:      ev.Outcome,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Details:      ev.Details,
	}
	anonymous := cfg != nil && cfg.IsAnonymousMode()
	if !anonymous {
		in.UserID = ev.UserID
		in.Username = ev.Username
		if r != nil {
			in.IPAddress = utils.GetClientIP(r)
			in.UserAgent = truncate(r.Header.Get("User-Agent"), 512)
		}
	}
	ctx := context.Background()
	if r != nil {
		// Don't lose the entry because the client disconnected.
		ctx = context.WithoutCancel(r.Context())
	}
	if _, err := l.Append(ctx, in); err != nil {
		writeFailures.Inc()
		slog.Error("failed to write audit log entry", "error", err, "event_type", ev.Type, "action", ev.Action)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
