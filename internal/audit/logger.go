package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
	// verifying allows one Verify at a time: it reads the whole log.
	verifying    sync.Mutex
	lastPruneErr atomic.Pointer[pruneError]
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

// Field limits, applied before signing. Several fields carry
// client-supplied text (a login form's username, a credential's name), and
// entries are kept for at least 30 days and read in full by Verify and
// export, so no one request may write an arbitrarily large entry.
const (
	maxShortField  = 64   // action, IP address, resource type
	maxMediumField = 256  // username, resource id
	maxUserAgent   = 512  // user agent
	maxDetails     = 8192 // details JSON
)

// Append signs and stores an entry. The entry is durable when it returns.
func (l *Logger) Append(ctx context.Context, in Entry) (*models.AuditLog, error) {
	e := &models.AuditLog{
		EventType:    in.Type,
		Action:       limit(clean(in.Action), maxShortField),
		Outcome:      in.Outcome,
		Username:     limit(clean(in.Username), maxMediumField),
		IPAddress:    limit(clean(in.IPAddress), maxShortField),
		UserAgent:    limit(clean(in.UserAgent), maxUserAgent),
		ResourceType: limit(clean(in.ResourceType), maxShortField),
		ResourceID:   limit(clean(in.ResourceID), maxMediumField),
		KeyID:        l.key.ID,
	}
	if in.UserID != 0 {
		e.UserID = strconv.FormatInt(in.UserID, 10)
	}
	if len(in.Details) > 0 {
		details, err := encodeDetails(in.Details)
		if err != nil {
			return nil, err
		}
		e.Details = details
	}
	// The timestamp is taken inside the append lock, with the id, so
	// timestamps are in chain order.
	sign := func(e *models.AuditLog) string {
		e.Timestamp = l.now().UTC().Format(TimestampFormat)
		return l.Sign(e)
	}
	if err := l.repo.Append(ctx, e, sign); err != nil {
		return nil, err
	}
	if l.appends.Add(1)%checkpointEvery == 0 {
		logCheckpoint("periodic", models.AuditAnchor{ID: e.ID, Hash: e.EntryHash})
	}
	return e, nil
}

// encodeDetails renders Details as JSON (sorted keys; <, > and & left as
// they are, so they can be searched for). Over maxDetails, it's replaced by
// a marker rather than cut into invalid JSON.
func encodeDetails(details map[string]any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(details); err != nil {
		return "", fmt.Errorf("failed to encode audit details: %w", err)
	}
	out := strings.TrimSuffix(buf.String(), "\n")
	if len(out) > maxDetails {
		return `{"truncated":true}`, nil
	}
	return clean(out), nil
}

// limit cuts s to at most n bytes without splitting a UTF-8 sequence.
func limit(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
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

// CheckKey warns if the newest entry was signed with a different key than
// the one loaded: every check of the log would then fail from that entry
// on (a lost key file, or instances that don't share AUDIT_LOG_KEY).
func (l *Logger) CheckKey(ctx context.Context) {
	latest, err := l.repo.List(ctx, models.AuditLogFilter{Limit: 1})
	if err != nil || len(latest) == 0 {
		return
	}
	if latest[0].KeyID != l.key.ID {
		slog.Error("audit log was last written with a different signing key; integrity checks will fail for entries signed with it. "+
			"Restore the previous audit.key or AUDIT_LOG_KEY, and give every instance the same AUDIT_LOG_KEY",
			"current_key_id", l.key.ID, "latest_entry_key_id", latest[0].KeyID, "latest_entry_id", latest[0].ID)
	}
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
	// Problem and ProblemID describe the first inconsistency found;
	// Problems lists up to maxReportedProblems of them and ProblemCount
	// says how many there were. Checking carries on past a problem, so one
	// bad entry can't hide tampering further along.
	Problem      string    `json:"problem,omitempty"`
	ProblemID    int64     `json:"problem_id,omitempty"`
	Problems     []Problem `json:"problems,omitempty"`
	ProblemCount int64     `json:"problem_count,omitempty"`
}

// Problem is one inconsistency found by Verify.
type Problem struct {
	ID          int64  `json:"id"`
	Description string `json:"description"`
}

const maxReportedProblems = 20

func (v *Verification) fail(id int64, format string, args ...any) {
	desc := fmt.Sprintf(format, args...)
	if v.Valid {
		v.Valid = false
		v.ProblemID, v.Problem = id, desc
	}
	v.ProblemCount++
	if len(v.Problems) < maxReportedProblems {
		v.Problems = append(v.Problems, Problem{ID: id, Description: desc})
	}
}

// chainChecker checks entries handed to it in id order, starting after an
// anchor: each must be the next id, linked to the one before, signed with
// this key, and unmodified. It reports every problem to fail and carries
// on from the entry as stored.
type chainChecker struct {
	l        *Logger
	prevID   int64
	prevHash string
	fail     func(id int64, format string, args ...any)
}

func (c *chainChecker) check(e *models.AuditLog) {
	if e.ID != c.prevID+1 {
		c.fail(c.prevID+1, "entries %d to %d are missing", c.prevID+1, e.ID-1)
	} else if e.PrevHash != c.prevHash {
		c.fail(e.ID, "entry %d is not linked to the entry before it", e.ID)
	}
	if e.KeyID != c.l.key.ID {
		// Not something to skip: key_id is just a column, so accepting
		// unknown keys would let anyone exempt a row from the check by
		// changing it.
		c.fail(e.ID, "entry %d was signed with a different key (%q); it can't be checked with the current key", e.ID, e.KeyID)
	} else if !hmac.Equal([]byte(c.l.Sign(e)), []byte(e.EntryHash)) {
		c.fail(e.ID, "entry %d has been modified", e.ID)
	}
	c.prevID, c.prevHash = e.ID, e.EntryHash
}

// pruneDetails is the Details of a retention prune entry.
type pruneDetails struct {
	ThroughID     int64  `json:"through_id"`
	ThroughHash   string `json:"through_hash"`
	Deleted       int64  `json:"deleted"`
	Before        string `json:"before,omitempty"`         // entries older than this were due
	RetentionDays int    `json:"retention_days,omitempty"` // the setting the prune used
}

// Verify checks every entry from the anchor to the head: ids contiguous,
// each linked to the previous entry's hash, each hash matching its
// contents, and, once retention has pruned anything, the anchor vouched for
// by the newest prune entry in the chain. It reports every problem found.
//
// It can't see entries removed from the newest end; the checkpoint lines
// in the application log are what catch that.
func (l *Logger) Verify(ctx context.Context) (*Verification, error) {
	if !l.verifying.TryLock() {
		return nil, ErrVerifyInProgress
	}
	defer l.verifying.Unlock()
	v, err := l.verifyOnce(ctx)
	if err == nil && !v.Valid {
		// The anchor and the entries are read separately, so a retention
		// prune landing in between looks like missing entries. Check
		// again before reporting tampering; real tampering fails twice.
		v, err = l.verifyOnce(ctx)
	}
	return v, err
}

// ErrVerifyInProgress is returned by Verify while another run is going.
var ErrVerifyInProgress = errors.New("audit log verification already in progress")

func (l *Logger) verifyOnce(ctx context.Context) (*Verification, error) {
	v := &Verification{Valid: true}
	anchor, err := l.repo.Anchor(ctx)
	if err != nil {
		return nil, err
	}

	// Entries at or before the starting point should all have been pruned.
	if stale, err := l.repo.List(ctx, models.AuditLogFilter{BeforeID: anchor.ID + 1, Limit: 1}); err != nil {
		return nil, err
	} else if len(stale) > 0 {
		v.fail(stale[0].ID, "entry %d is at or before the chain's starting point (%d), which should have been pruned", stale[0].ID, anchor.ID)
	}

	c := &chainChecker{l: l, prevID: anchor.ID, prevHash: anchor.Hash, fail: v.fail}
	var lastPrune *pruneDetails
	var lastPruneID int64
	for {
		entries, err := l.repo.Range(ctx, c.prevID, 1000)
		if err != nil {
			return nil, err
		}
		if len(entries) == 0 {
			break
		}
		for i := range entries {
			e := &entries[i]
			if v.Checked == 0 {
				v.FirstID = e.ID
			}
			c.check(e)
			if e.EventType == models.AuditEventSystem && e.Action == PruneAction {
				var d pruneDetails
				if err := json.Unmarshal([]byte(e.Details), &d); err == nil {
					lastPrune, lastPruneID = &d, e.ID
				}
			}
			v.Checked++
		}
	}
	v.LastID, v.LastHash = c.prevID, c.prevHash

	if anchor.ID > 0 {
		if lastPrune == nil {
			v.fail(anchor.ID+1, "entries up to %d were removed without a recorded retention prune", anchor.ID)
		} else if lastPrune.ThroughID != anchor.ID || lastPrune.ThroughHash != anchor.Hash {
			v.fail(lastPruneID, "the chain's starting point doesn't match the last recorded retention prune (entry %d)", lastPruneID)
		}
	}
	return v, nil
}

// Retention limits: 0 keeps entries forever; otherwise at least
// MinRetentionDays, so recent history can't be pruned away by shortening
// it - enforced here as well as in the admin API, since the setting lives in
// an unsigned table.
const (
	MinRetentionDays = 30
	MaxRetentionDays = 36500
)

// ValidRetentionDays reports whether days is an allowed retention period.
func ValidRetentionDays(days int) bool {
	return days == 0 || (days >= MinRetentionDays && days <= MaxRetentionDays)
}

// pruneBatch caps how many entries one prune transaction deletes, so the
// append lock is never held for long; Prune repeats until done. (A
// variable so tests can lower it.)
var pruneBatch int64 = 10000

// Prune deletes entries older than the retention period, recording each
// prune in the chain. It returns how many were deleted. A failure is
// counted and kept for the admin Audit Log tab (LastPruneError): pruning
// refuses rather than discard entries it can't vouch for, so retention
// stops until the problem is looked at.
func (l *Logger) Prune(ctx context.Context) (int64, error) {
	deleted, err := l.prune(ctx)
	if err != nil {
		pruneFailures.Inc()
		l.lastPruneErr.Store(&pruneError{err: err.Error(), at: l.now().UTC().Format(TimestampFormat)})
	} else {
		l.lastPruneErr.Store(nil)
	}
	return deleted, err
}

// LastPruneError returns the most recent prune failure and when it
// happened, or "" if the last prune succeeded.
func (l *Logger) LastPruneError() (string, string) {
	if p := l.lastPruneErr.Load(); p != nil {
		return p.err, p.at
	}
	return "", ""
}

type pruneError struct{ err, at string }

func (l *Logger) prune(ctx context.Context) (int64, error) {
	days, err := l.repo.RetentionDays(ctx)
	if err != nil || days == 0 {
		return 0, err
	}
	if !ValidRetentionDays(days) {
		return 0, fmt.Errorf("refusing to prune: stored retention of %d days is outside the allowed range (0 or %d-%d)",
			days, MinRetentionDays, MaxRetentionDays)
	}
	before := l.now().UTC().AddDate(0, 0, -days).Format(TimestampFormat)

	var total int64
	for {
		deleted, err := l.repo.Prune(ctx, before, pruneBatch, l.pruneChecker, func(anchor models.AuditAnchor, deleted int64) *models.AuditLog {
			d, _ := json.Marshal(pruneDetails{ThroughID: anchor.ID, ThroughHash: anchor.Hash, Deleted: deleted,
				Before: before, RetentionDays: days})
			return &models.AuditLog{
				EventType: models.AuditEventSystem,
				Action:    PruneAction,
				Outcome:   models.AuditOutcomeSuccess,
				Details:   string(d),
				KeyID:     l.key.ID,
			}
		}, func(e *models.AuditLog) string {
			e.Timestamp = l.now().UTC().Format(TimestampFormat)
			return l.Sign(e)
		})
		total += deleted
		if err != nil {
			return total, err
		}
		if deleted > 0 {
			slog.Info("audit log retention prune", "deleted", deleted, "retention_days", days)
			l.Checkpoint(ctx, "retention_prune")
		}
		if deleted < pruneBatch {
			return total, nil
		}
	}
}

// pruneChecker vets a prune before anything is deleted, inside its
// transaction. The anchor it starts from lives in an unsigned table, so it
// must be vouched for by the newest signed prune entry (or still be the
// genesis anchor, with no prune ever recorded); otherwise deleting entries
// and moving the anchor by hand would be legitimised by the next prune.
// Then every entry to be deleted must check out, so tampered or backdated
// entries can't be pruned away under a validly signed prune record either.
func (l *Logger) pruneChecker(anchor models.AuditAnchor, lastPrune *models.AuditLog) (func(*models.AuditLog) error, error) {
	if lastPrune == nil {
		if anchor.ID != 0 || anchor.Hash != repository.AuditGenesisHash {
			return nil, fmt.Errorf("refusing to prune: the chain starts after entry %d but no retention prune is recorded", anchor.ID)
		}
	} else {
		var d pruneDetails
		switch {
		case lastPrune.KeyID != l.key.ID || !hmac.Equal([]byte(l.Sign(lastPrune)), []byte(lastPrune.EntryHash)):
			return nil, fmt.Errorf("refusing to prune: the last retention prune entry (%d) doesn't verify", lastPrune.ID)
		case json.Unmarshal([]byte(lastPrune.Details), &d) != nil || d.ThroughID != anchor.ID || d.ThroughHash != anchor.Hash || lastPrune.ID <= anchor.ID:
			return nil, fmt.Errorf("refusing to prune: the chain's starting point doesn't match the last retention prune (entry %d)", lastPrune.ID)
		}
	}

	var problem error
	c := &chainChecker{l: l, prevID: anchor.ID, prevHash: anchor.Hash, fail: func(id int64, format string, args ...any) {
		if problem == nil {
			problem = fmt.Errorf("refusing to prune: "+format, args...)
		}
	}}
	return func(e *models.AuditLog) error {
		c.check(e)
		return problem
	}, nil
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
