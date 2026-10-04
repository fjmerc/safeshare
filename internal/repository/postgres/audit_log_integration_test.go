//go:build integration
// +build integration

package postgres

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/models"
)

func newAuditTestLogger(t *testing.T) *audit.Logger {
	t.Helper()
	repos := setupTestRepos(t)
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE audit_log_state SET anchor_id = 0, anchor_hash = $1, retention_days = 365 WHERE id = 1`,
		strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	key, err := audit.LoadKey(strings.Repeat("ab", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	return audit.NewLogger(repos.AuditLogs, key)
}

// ADR-018 on PostgreSQL: concurrent appends form one chain, entries read
// back verify (values survive the round trip exactly as signed), and edits,
// deletions and unknown-key rows are caught.
func TestAuditLog_Postgres(t *testing.T) {
	l := newAuditTestLogger(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				if _, err := l.Append(ctx, audit.Entry{
					Type: models.AuditEventAuth, Action: "login", Outcome: models.AuditOutcomeSuccess,
					UserID: int64(w + 1), Username: "ünïcode-user", IPAddress: "2001:db8::1",
					Details: map[string]any{"worker": w, "i": i, "note": "tab\tand \"quotes\""},
				}); err != nil {
					t.Error(err)
				}
			}
		}(w)
	}
	wg.Wait()

	v, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid || v.Checked != 40 || v.LastID != 40 {
		t.Fatalf("verify = %+v, want 40 contiguous valid entries", v)
	}

	for _, tc := range []struct {
		name, sql string
		want      string
	}{
		{"edit", `UPDATE audit_logs SET details = '{}' WHERE id = 10`, "entry 10 has been modified"},
		{"key swap", `UPDATE audit_logs SET key_id = 'feedfacefeedface' WHERE id = 10`, "entry 10 was signed with a different key"},
		{"delete", `DELETE FROM audit_logs WHERE id = 10`, "entries 10 to 10 are missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err := tx.Exec(ctx, tc.sql); err != nil {
				t.Fatal(err)
			}
			// Verify reads through the pool, so commit the tamper, check,
			// then undo it by restoring from the still-valid copy below.
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			v, err := l.Verify(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if v.Valid || !strings.Contains(v.Problem, tc.want) {
				t.Fatalf("verify = %+v, want problem %q", v, tc.want)
			}
		})
		// Each case starts from a fresh, valid log.
		l = newAuditTestLogger(t)
		for i := 0; i < 12; i++ {
			if _, err := l.Append(ctx, audit.Entry{Type: models.AuditEventFile, Action: "upload", Outcome: models.AuditOutcomeSuccess}); err != nil {
				t.Fatal(err)
			}
		}
	}
}
