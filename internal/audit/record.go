package audit

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

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

// appendTimeout bounds how long recording one event may take.
const appendTimeout = 5 * time.Second

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
// anonymous mode it stores nothing that identifies a person (see
// anonymize).
//
// It returns once the entry is durable. If it can't be written, that is
// logged and counted but the request carries on: an audit log that can't
// keep up must not lock everyone out of logging in.
func Record(r *http.Request, cfg *config.Config, ev Event) {
	if Default() == nil {
		return
	}
	ip, ua := "", ""
	ctx := context.Background()
	if r != nil {
		ip = utils.GetClientIP(r)
		ua = r.Header.Get("User-Agent")
		// Don't lose the entry because the client disconnected.
		ctx = context.WithoutCancel(r.Context())
	}
	RecordFor(ctx, cfg, ip, ua, ev)
}

// RecordFor is Record for code with no request in hand (e.g. the chunked
// upload assembly worker): ip and userAgent describe whoever caused the
// event.
func RecordFor(ctx context.Context, cfg *config.Config, ip, userAgent string, ev Event) {
	l := Default()
	if l == nil {
		return
	}
	in := Entry{
		Type:         ev.Type,
		Action:       ev.Action,
		Outcome:      ev.Outcome,
		UserID:       ev.UserID,
		Username:     ev.Username,
		IPAddress:    ip,
		UserAgent:    userAgent,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Details:      ev.Details,
	}
	// Fail closed: without a config, assume anonymous mode.
	if cfg == nil || cfg.IsAnonymousMode() {
		anonymize(&in)
	}
	// Bounded: a stalled database must turn into a counted, logged write
	// failure, not a request that hangs.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), appendTimeout)
	defer cancel()
	if _, err := l.Append(ctx, in); err != nil {
		writeFailures.Inc()
		slog.Error("failed to write audit log entry", "error", err, "event_type", ev.Type, "action", ev.Action)
	}
}

// Resource types whose ids identify a person or an address.
var identifyingResourceTypes = map[string]bool{
	"user":                true,
	"mfa":                 true,
	"webauthn_credential": true,
	"token":               true,
	"ip":                  true,
}

// IdentifyingDetailKeys are Details keys that identify a person or an
// address; hooks must use these names for such values so anonymous mode
// can strip them.
// Filenames and an export's query (which may hold a username or IP
// filter) are dropped too.
var IdentifyingDetailKeys = []string{"target_username", "username", "user_id", "owner_id", "ip", "ips", "name", "filename", "query"}

// anonymize removes everything identifying a person from an entry,
// keeping what happened: no requester address, account, username or user
// agent, no id of a user, credential, token or IP the action was about, and
// none of IdentifyingDetailKeys.
func anonymize(e *Entry) {
	e.UserID, e.Username, e.IPAddress, e.UserAgent = 0, "", "", ""
	if identifyingResourceTypes[e.ResourceType] {
		e.ResourceID = ""
	}
	if len(e.Details) > 0 {
		d := make(map[string]any, len(e.Details))
		for k, v := range e.Details {
			d[k] = v
		}
		for _, k := range IdentifyingDetailKeys {
			delete(d, k)
		}
		e.Details = d
	}
}
