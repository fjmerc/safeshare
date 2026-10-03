package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func testKey(t *testing.T) Key {
	t.Helper()
	k, err := LoadKey(strings.Repeat("ab", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestLogger(t *testing.T) (*Logger, *sql.DB) {
	t.Helper()
	db := testutil.SetupTestDB(t)
	return NewLogger(sqlite.NewAuditLogRepository(db), testKey(t)), db
}

func appendN(t *testing.T, l *Logger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := l.Append(context.Background(), Entry{
			Type: models.AuditEventAuth, Action: "login", Outcome: models.AuditOutcomeSuccess,
			UserID: int64(i + 1), Username: fmt.Sprintf("user%d", i), IPAddress: "192.0.2.1",
			Details: map[string]any{"n": i},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func mustVerify(t *testing.T, l *Logger) *Verification {
	t.Helper()
	v, err := l.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func exec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func TestVerify_IntactChain(t *testing.T) {
	l, _ := newTestLogger(t)
	if v := mustVerify(t, l); !v.Valid || v.Checked != 0 {
		t.Fatalf("empty log: %+v", v)
	}
	appendN(t, l, 10)
	v := mustVerify(t, l)
	if !v.Valid || v.Checked != 10 || v.FirstID != 1 || v.LastID != 10 {
		t.Fatalf("verify = %+v, want valid 1..10", v)
	}
}

func TestVerify_DetectsTampering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper func(t *testing.T, db *sql.DB)
		wantID int64
		want   string
	}{
		{"edited details", func(t *testing.T, db *sql.DB) {
			exec(t, db, `UPDATE audit_logs SET details = '{"n":99}' WHERE id = 4`)
		}, 4, "modified"},
		{"edited outcome", func(t *testing.T, db *sql.DB) {
			exec(t, db, `UPDATE audit_logs SET outcome = 'FAILURE' WHERE id = 7`)
		}, 7, "modified"},
		{"deleted middle entry", func(t *testing.T, db *sql.DB) {
			exec(t, db, `DELETE FROM audit_logs WHERE id = 5`)
		}, 5, "missing"},
		{"deleted oldest entries", func(t *testing.T, db *sql.DB) {
			exec(t, db, `DELETE FROM audit_logs WHERE id <= 3`)
		}, 1, "missing"},
		{"deleted oldest entries and moved the anchor", func(t *testing.T, db *sql.DB) {
			var hash string
			if err := db.QueryRow(`SELECT entry_hash FROM audit_logs WHERE id = 3`).Scan(&hash); err != nil {
				t.Fatal(err)
			}
			exec(t, db, `DELETE FROM audit_logs WHERE id <= 3`)
			exec(t, db, `UPDATE audit_log_state SET anchor_id = 3, anchor_hash = ? WHERE id = 1`, hash)
		}, 4, "without a recorded retention prune"},
		{"swapped key id to dodge the check", func(t *testing.T, db *sql.DB) {
			exec(t, db, `UPDATE audit_logs SET details = '{"n":99}', key_id = 'feedfacefeedface' WHERE id = 6`)
		}, 6, "different key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, db := newTestLogger(t)
			appendN(t, l, 10)
			tc.tamper(t, db)
			v := mustVerify(t, l)
			if v.Valid {
				t.Fatalf("verify passed after tampering: %+v", v)
			}
			if v.ProblemID != tc.wantID || !strings.Contains(v.Problem, tc.want) {
				t.Errorf("problem = %d %q, want %d containing %q", v.ProblemID, v.Problem, tc.wantID, tc.want)
			}
		})
	}
}

// Without the secret key, an attacker with database write access can at
// most rebuild the chain with some other key - which must not verify.
func TestVerify_RechainedWithoutKeyFails(t *testing.T) {
	l, db := newTestLogger(t)
	appendN(t, l, 5)
	exec(t, db, `UPDATE audit_logs SET username = 'someone-else' WHERE id = 2`)

	// Re-sign every entry in order, as a forger without the key would.
	forged := NewLogger(sqlite.NewAuditLogRepository(db), Key{secret: []byte("guess"), ID: l.KeyID()})
	entries, err := sqlite.NewAuditLogRepository(db).Range(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	prev := entries[0].PrevHash
	for i := range entries {
		e := &entries[i]
		e.PrevHash = prev
		e.EntryHash = forged.Sign(e)
		// Plain SHA-256 of the same encoding is no better.
		if i%2 == 1 {
			sum := sha256.Sum256([]byte(e.EntryHash))
			e.EntryHash = hex.EncodeToString(sum[:])
		}
		exec(t, db, `UPDATE audit_logs SET prev_hash = ?, entry_hash = ? WHERE id = ?`, e.PrevHash, e.EntryHash, e.ID)
		prev = e.EntryHash
	}

	if v := mustVerify(t, l); v.Valid || v.ProblemID != 1 {
		t.Fatalf("verify = %+v, want failure at entry 1", v)
	}
}

// Appends from many goroutines, over separate connections to a real
// database file (as in production), must still form one contiguous chain.
func TestAppend_ConcurrentWritersKeepOneChain(t *testing.T) {
	db, err := database.Initialize(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	l := NewLogger(sqlite.NewAuditLogRepository(db), testKey(t))

	const writers, each = 10, 5
	var wg sync.WaitGroup
	errs := make(chan error, writers*each)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if _, err := l.Append(context.Background(), Entry{Type: models.AuditEventFile, Action: "upload", Outcome: models.AuditOutcomeSuccess}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if v := mustVerify(t, l); !v.Valid || v.Checked != writers*each || v.LastID != writers*each {
		t.Fatalf("verify = %+v, want %d contiguous valid entries", v, writers*each)
	}
}

func TestPrune_KeepsChainVerifiable(t *testing.T) {
	l, db := newTestLogger(t)
	repo := sqlite.NewAuditLogRepository(db)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return start }
	appendN(t, l, 5) // old
	l.now = func() time.Time { return start.AddDate(0, 0, 40) }
	appendN(t, l, 3) // recent
	if err := repo.SetRetentionDays(context.Background(), 30); err != nil {
		t.Fatal(err)
	}

	deleted, err := l.Prune(context.Background())
	if err != nil || deleted != 5 {
		t.Fatalf("Prune = %d, %v; want 5 deleted", deleted, err)
	}
	v := mustVerify(t, l)
	if !v.Valid || v.FirstID != 6 || v.Checked != 4 {
		t.Fatalf("after prune verify = %+v, want valid from 6 with the prune entry", v)
	}
	if again, _ := l.Prune(context.Background()); again != 0 {
		t.Errorf("second prune deleted %d, want 0", again)
	}

	// Deleting more of the oldest entries and moving the anchor to match
	// is caught: the recorded prune vouches for the old anchor only.
	var hash string
	if err := db.QueryRow(`SELECT entry_hash FROM audit_logs WHERE id = 6`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	exec(t, db, `DELETE FROM audit_logs WHERE id = 6`)
	exec(t, db, `UPDATE audit_log_state SET anchor_id = 6, anchor_hash = ? WHERE id = 1`, hash)
	if v := mustVerify(t, l); v.Valid || !strings.Contains(v.Problem, "doesn't match the last recorded retention prune") {
		t.Fatalf("verify after extra deletion = %+v, want anchor mismatch", v)
	}
}

func TestPrune_ForeverKeepsEverything(t *testing.T) {
	l, db := newTestLogger(t)
	l.now = func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }
	appendN(t, l, 3)
	l.now = time.Now
	if err := sqlite.NewAuditLogRepository(db).SetRetentionDays(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if deleted, err := l.Prune(context.Background()); err != nil || deleted != 0 {
		t.Fatalf("Prune with retention 0 = %d, %v; want nothing deleted", deleted, err)
	}
}

func TestRecord_AnonymousModeStoresNoIdentity(t *testing.T) {
	l, db := newTestLogger(t)
	SetDefault(l)
	defer SetDefault(nil)
	cfg := testutil.SetupTestConfig(t)

	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = "198.51.100.7:4444"
	req.Header.Set("User-Agent", "agent/1.0")
	ev := Event{Type: models.AuditEventAuth, Action: "login", Outcome: models.AuditOutcomeFailure, UserID: 42, Username: "alice"}

	Record(req, cfg, ev)
	t.Setenv("ANONYMOUS_MODE", "true")
	anonCfg := testutil.SetupTestConfig(t)
	if !anonCfg.IsAnonymousMode() {
		t.Fatal("ANONYMOUS_MODE not picked up")
	}
	Record(req, anonCfg, ev)

	entries, err := sqlite.NewAuditLogRepository(db).Range(context.Background(), 0, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %d, %v", len(entries), err)
	}
	normal, anon := entries[0], entries[1]
	if normal.Username != "alice" || normal.UserID != "42" || normal.IPAddress == "" || normal.UserAgent != "agent/1.0" {
		t.Errorf("normal entry = %+v, want identity recorded", normal)
	}
	if anon.Username != "" || anon.UserID != "" || anon.IPAddress != "" || anon.UserAgent != "" {
		t.Errorf("anonymous-mode entry = %+v, want no identity", anon)
	}
	if v := mustVerify(t, l); !v.Valid {
		t.Errorf("verify = %+v", v)
	}
}

func TestAppend_UnstorableTextIsCleanedAndVerifies(t *testing.T) {
	l, _ := newTestLogger(t)
	e, err := l.Append(context.Background(), Entry{Type: models.AuditEventAuth, Action: "login",
		Outcome: models.AuditOutcomeFailure, Username: "bad\x00name\xff"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(e.Username, 0) || !strings.HasPrefix(e.Username, "bad") {
		t.Errorf("username stored as %q", e.Username)
	}
	if v := mustVerify(t, l); !v.Valid {
		t.Errorf("verify = %+v", v)
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadKey("", dir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, KeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
	}
	k2, err := LoadKey("", dir)
	if err != nil || k2.ID != k1.ID {
		t.Fatalf("reloaded key = %v, %v; want the same key", k2.ID, err)
	}

	env, err := LoadKey(strings.Repeat("0f", 32), dir)
	if err != nil || env.ID == k1.ID || env.Source != "AUDIT_LOG_KEY" {
		t.Errorf("env key = %+v, %v; want it to take precedence", env, err)
	}
	for _, bad := range []string{"xyz", strings.Repeat("ab", 16)} {
		if _, err := LoadKey(bad, dir); err == nil {
			t.Errorf("LoadKey(%q) = nil error, want rejection", bad)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFileName), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey("", dir); err == nil {
		t.Error("LoadKey with a corrupt key file = nil error, want failure")
	}
}

func TestAnonymize_StripsIdentityKeepsWhatHappened(t *testing.T) {
	e := Entry{
		Type: models.AuditEventAdmin, Action: "user_delete", Outcome: models.AuditOutcomeSuccess,
		UserID: 1, Username: "admin", IPAddress: "198.51.100.1", UserAgent: "ua",
		ResourceType: "user", ResourceID: "42",
		Details: map[string]any{"target_username": "alice", "owner_id": 42, "name": "laptop", "role": "user", "count": 3},
	}
	original := e.Details
	anonymize(&e)
	if e.UserID != 0 || e.Username != "" || e.IPAddress != "" || e.UserAgent != "" || e.ResourceID != "" {
		t.Errorf("identity kept: %+v", e)
	}
	for _, k := range IdentifyingDetailKeys {
		if _, ok := e.Details[k]; ok {
			t.Errorf("details still has %q", k)
		}
	}
	if e.Details["role"] != "user" || e.Details["count"] != 3 || e.Action != "user_delete" {
		t.Errorf("non-identifying data lost: %+v", e)
	}
	if original["target_username"] != "alice" {
		t.Error("anonymize modified the caller's Details map")
	}

	file := Entry{ResourceType: "file", ResourceID: "7"}
	anonymize(&file)
	if file.ResourceID != "7" {
		t.Errorf("file id stripped: %q", file.ResourceID)
	}
}

func TestAppend_CapsFieldSizes(t *testing.T) {
	l, _ := newTestLogger(t)
	e, err := l.Append(context.Background(), Entry{
		Type: models.AuditEventAuth, Action: "login", Outcome: models.AuditOutcomeFailure,
		Username: strings.Repeat("é", 1000), // 2000 bytes, multi-byte
		Details:  map[string]any{"name": strings.Repeat("x", 20000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Username) > maxMediumField || !utf8.ValidString(e.Username) {
		t.Errorf("username stored as %d bytes, valid UTF-8 %v", len(e.Username), utf8.ValidString(e.Username))
	}
	if e.Details != `{"truncated":true}` {
		t.Errorf("oversized details stored as %d bytes: %.40q", len(e.Details), e.Details)
	}
	if v := mustVerify(t, l); !v.Valid {
		t.Errorf("verify = %+v", v)
	}
}

// The retention setting lives in an unsigned table: a value below the
// floor, however it got there, must not prune recent history.
func TestPrune_RefusesRetentionBelowFloor(t *testing.T) {
	l, db := newTestLogger(t)
	l.now = func() time.Time { return time.Now().AddDate(0, 0, -5) }
	appendN(t, l, 3)
	l.now = time.Now
	exec(t, db, `UPDATE audit_log_state SET retention_days = 1 WHERE id = 1`)
	deleted, err := l.Prune(context.Background())
	if err == nil || deleted != 0 {
		t.Fatalf("Prune with retention 1 = %d, %v; want refusal", deleted, err)
	}
	if v := mustVerify(t, l); !v.Valid || v.Checked != 3 {
		t.Errorf("verify = %+v, want all 3 entries kept", v)
	}
	for days, want := range map[int]bool{0: true, 29: false, 30: true, 36500: true, 36501: false, -1: false} {
		if got := ValidRetentionDays(days); got != want {
			t.Errorf("ValidRetentionDays(%d) = %v, want %v", days, got, want)
		}
	}
}

func TestPrune_EverythingThenMoreAndAgain(t *testing.T) {
	l, db := newTestLogger(t)
	repo := sqlite.NewAuditLogRepository(db)
	if err := repo.SetRetentionDays(context.Background(), 30); err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return day }
	appendN(t, l, 4)

	// Everything is old: the log is left holding just the prune entry.
	day = day.AddDate(0, 0, 40)
	if n, err := l.Prune(context.Background()); err != nil || n != 4 {
		t.Fatalf("first prune = %d, %v", n, err)
	}
	appendN(t, l, 2)
	if v := mustVerify(t, l); !v.Valid || v.FirstID != 5 || v.Checked != 3 {
		t.Fatalf("after full prune verify = %+v", v)
	}

	// A later prune removes the first prune entry too; the newest one now
	// vouches for the anchor.
	day = day.AddDate(0, 0, 40)
	if n, err := l.Prune(context.Background()); err != nil || n != 3 {
		t.Fatalf("second prune = %d, %v", n, err)
	}
	if v := mustVerify(t, l); !v.Valid || v.FirstID != 8 || v.Checked != 1 {
		t.Fatalf("after second prune verify = %+v", v)
	}
}

func TestVerify_OneAtATime(t *testing.T) {
	l, _ := newTestLogger(t)
	l.verifying.Lock()
	_, err := l.Verify(context.Background())
	l.verifying.Unlock()
	if err != ErrVerifyInProgress {
		t.Fatalf("Verify while another runs = %v, want ErrVerifyInProgress", err)
	}
}

func TestAppend_TimestampsFollowChainOrder(t *testing.T) {
	db, err := database.Initialize(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := sqlite.NewAuditLogRepository(db)
	l := NewLogger(repo, testKey(t))
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				_, _ = l.Append(context.Background(), Entry{Type: models.AuditEventFile, Action: "upload", Outcome: models.AuditOutcomeSuccess})
			}
		}()
	}
	wg.Wait()
	entries, err := repo.Range(context.Background(), 0, 100)
	if err != nil || len(entries) != 40 {
		t.Fatalf("entries = %d, %v", len(entries), err)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].Timestamp < entries[i-1].Timestamp {
			t.Errorf("entry %d (%s) is timestamped before entry %d (%s)", entries[i].ID, entries[i].Timestamp, entries[i-1].ID, entries[i-1].Timestamp)
		}
	}
}
