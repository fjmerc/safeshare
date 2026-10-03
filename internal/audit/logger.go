package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// TimestampFormat is how entry timestamps are stored and hashed: fixed
// width, UTC, microseconds, so they sort as text and survive both databases
// unchanged.
const TimestampFormat = "2006-01-02T15:04:05.000000Z"

// checkpointEvery is how many appends pass between checkpoint log lines.
const checkpointEvery = 100

// PruneAction is the action of the SYSTEM entry each retention prune writes.
const PruneAction = "retention_prune"

// Logger appends to and verifies the audit log.
type Logger struct {
	repo    repository.AuditLogRepository
	key     Key
	now     func() time.Time
	appends atomic.Int64
}

// NewLogger creates a Logger signing with key.
func NewLogger(repo repository.AuditLogRepository, key Key) *Logger {
	return &Logger{repo: repo, key: key, now: time.Now}
}

// KeyID identifies the signing key.
func (l *Logger) KeyID() string { return l.key.ID }

// Sign returns the entry hash: an HMAC-SHA256, under the audit key, of every
// field of e (including its id and the previous entry's hash), each length
// prefixed so no two different entries encode alike.
func (l *Logger) Sign(e *models.AuditLog) string {
	return signWith(l.key.secret, e)
}

func signWith(secret []byte, e *models.AuditLog) string {
	mac := hmac.New(sha256.New, secret)
	for _, field := range []string{
		"safeshare-audit-v1",
		strconv.FormatInt(e.ID, 10),
		e.Timestamp,
		string(e.EventType),
		e.Action,
		string(e.Outcome),
		e.UserID,
		e.Username,
		e.IPAddress,
		e.UserAgent,
		e.ResourceType,
		e.ResourceID,
		e.Details,
		e.PrevHash,
	} {
		fmt.Fprintf(mac, "%d:%s;", len(field), field)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// Entry is what a caller records; Record fills in the rest.
type Entry struct {
	Type         models.AuditEventType
	Action       string
	Outcome      models.AuditOutcome
	UserID       int64 // 0 for none
	Username     string
	IPAddress    string
	UserAgent    string
	ResourceType string
	ResourceID   string
	Details      map[string]any
}

// Append signs and stores an entry. The entry is durable when it returns.
func (l *Logger) Append(ctx context.Context, in Entry) (*models.AuditLog, error) {
	e := &models.AuditLog{
		Timestamp:    l.now().UTC().Format(TimestampFormat),
		EventType:    in.Type,
		Action:       clean(in.Action),
		Outcome:      in.Outcome,
		Username:     clean(in.Username),
		IPAddress:    clean(in.IPAddress),
		UserAgent:    clean(in.UserAgent),
		ResourceType: clean(in.ResourceType),
		ResourceID:   clean(in.ResourceID),
		KeyID:        l.key.ID,
	}
	if in.UserID != 0 {
		e.UserID = strconv.FormatInt(in.UserID, 10)
	}
	if len(in.Details) > 0 {
		// encoding/json sorts map keys, so this is deterministic; the
		// stored text is what gets hashed either way.
		data, err := json.Marshal(in.Details)
		if err != nil {
			return nil, fmt.Errorf("failed to encode audit details: %w", err)
		}
		e.Details = string(data)
	}
	if err := l.repo.Append(ctx, e, l.Sign); err != nil {
		return nil, err
	}
	if l.appends.Add(1)%checkpointEvery == 0 {
		logCheckpoint("periodic", models.AuditAnchor{ID: e.ID, Hash: e.EntryHash})
	}
	return e, nil
}

// clean makes client-supplied text storable unchanged in both databases
// (PostgreSQL TEXT rejects NUL bytes and invalid UTF-8), so what is read
// back still matches what was signed.
func clean(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", "\uFFFD")
}

// logCheckpoint writes the chain head to the application log. Once those
// log lines are kept somewhere else, rewriting or truncating the audit
// table can be caught by comparing with them, even by someone holding the
// key.
func logCheckpoint(reason string, head models.AuditAnchor) {
	slog.Info("audit log checkpoint", "reason", reason, "id", head.ID, "entry_hash", head.Hash)
}

// Checkpoint logs the current chain head.
func (l *Logger) Checkpoint(ctx context.Context, reason string) {
	head, err := l.repo.Head(ctx)
	if err != nil {
		slog.Error("failed to read audit log head for checkpoint", "error", err)
		return
	}
	logCheckpoint(reason, head)
}

// Verification is the result of checking the whole audit log.
type Verification struct {
	Valid    bool   `json:"valid"`
	Checked  int64  `json:"checked"`
	FirstID  int64  `json:"first_id,omitempty"`
	LastID   int64  `json:"last_id,omitempty"`
	LastHash string `json:"last_hash,omitempty"`
	// Problem describes the first inconsistency found; ProblemID is the
	// entry it was found at.
	Problem   string `json:"problem,omitempty"`
	ProblemID int64  `json:"problem_id,omitempty"`
}

func (v *Verification) fail(id int64, format string, args ...any) *Verification {
	v.Valid = false
	v.ProblemID = id
	v.Problem = fmt.Sprintf(format, args...)
	return v
}

// pruneDetails is the Details of a retention prune entry.
type pruneDetails struct {
	ThroughID   int64  `json:"through_id"`
	ThroughHash string `json:"through_hash"`
	Deleted     int64  `json:"deleted"`
}

// Verify checks every entry from the anchor to the head: ids contiguous,
// each linked to the previous entry's hash, each hash matching its
// contents, and, once retention has pruned anything, the anchor vouched for
// by the newest prune entry in the chain. It stops at the first problem.
//
// It can't see entries removed from the newest end; the checkpoint lines
// in the application log are what catch that.
func (l *Logger) Verify(ctx context.Context) (*Verification, error) {
	v := &Verification{Valid: true}
	anchor, err := l.repo.Anchor(ctx)
	if err != nil {
		return nil, err
	}

	prevID, prevHash := anchor.ID, anchor.Hash
	var lastPrune *pruneDetails
	var lastPruneID int64
	const batch = 1000
	for {
		entries, err := l.repo.Range(ctx, prevID, batch)
		if err != nil {
			return nil, err
		}
		for i := range entries {
			e := &entries[i]
			if v.Checked == 0 {
				v.FirstID = e.ID
			}
			if e.ID != prevID+1 {
				return v.fail(prevID+1, "entries %d to %d are missing", prevID+1, e.ID-1), nil
			}
			if e.PrevHash != prevHash {
				return v.fail(e.ID, "entry %d is not linked to the entry before it", e.ID), nil
			}
			if e.KeyID != l.key.ID {
				// Not something to skip: key_id is just a column, so
				// accepting unknown keys would let anyone exempt a row
				// from the check by changing it.
				return v.fail(e.ID, "entry %d was signed with a different key (%q); it can't be checked with the current key", e.ID, e.KeyID), nil
			}
			if !hmac.Equal([]byte(l.Sign(e)), []byte(e.EntryHash)) {
				return v.fail(e.ID, "entry %d has been modified", e.ID), nil
			}
			if e.EventType == models.AuditEventSystem && e.Action == PruneAction {
				var d pruneDetails
				if err := json.Unmarshal([]byte(e.Details), &d); err == nil {
					lastPrune, lastPruneID = &d, e.ID
				}
			}
			prevID, prevHash = e.ID, e.EntryHash
			v.Checked++
		}
		if len(entries) < batch {
			break
		}
	}
	v.LastID, v.LastHash = prevID, prevHash

	if anchor.ID > 0 {
		if lastPrune == nil {
			return v.fail(anchor.ID+1, "entries up to %d were removed without a recorded retention prune", anchor.ID), nil
		}
		if lastPrune.ThroughID != anchor.ID || lastPrune.ThroughHash != anchor.Hash {
			return v.fail(lastPruneID, "the chain's starting point doesn't match the last recorded retention prune (entry %d)", lastPruneID), nil
		}
	}
	return v, nil
}

// Prune deletes entries older than the retention period, recording the
// prune in the chain. It returns how many were deleted.
func (l *Logger) Prune(ctx context.Context) (int64, error) {
	days, err := l.repo.RetentionDays(ctx)
	if err != nil || days <= 0 {
		return 0, err
	}
	before := l.now().UTC().AddDate(0, 0, -days).Format(TimestampFormat)
	deleted, err := l.repo.Prune(ctx, before, func(anchor models.AuditAnchor, deleted int64) *models.AuditLog {
		d, _ := json.Marshal(pruneDetails{ThroughID: anchor.ID, ThroughHash: anchor.Hash, Deleted: deleted})
		return &models.AuditLog{
			Timestamp: l.now().UTC().Format(TimestampFormat),
			EventType: models.AuditEventSystem,
			Action:    PruneAction,
			Outcome:   models.AuditOutcomeSuccess,
			Details:   string(d),
			KeyID:     l.key.ID,
		}
	}, l.Sign)
	if err != nil {
		return 0, err
	}
	if deleted > 0 {
		slog.Info("audit log retention prune", "deleted", deleted, "retention_days", days)
		l.Checkpoint(ctx, "retention_prune")
	}
	return deleted, nil
}

// Run checkpoints hourly and prunes daily until ctx is done, then writes a
// final checkpoint.
func (l *Logger) Run(ctx context.Context) {
	l.Checkpoint(ctx, "startup")
	if _, err := l.Prune(ctx); err != nil {
		slog.Error("audit log retention prune failed", "error", err)
	}
	hourly := time.NewTicker(time.Hour)
	defer hourly.Stop()
	hours := 0
	for {
		select {
		case <-ctx.Done():
			l.Checkpoint(context.Background(), "shutdown")
			return
		case <-hourly.C:
			l.Checkpoint(ctx, "hourly")
			if hours++; hours%24 == 0 {
				if _, err := l.Prune(ctx); err != nil {
					slog.Error("audit log retention prune failed", "error", err)
				}
			}
		}
	}
}
