package sqlite

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestNormalizeBlockedIPs_CanonicalizesInPlace(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)`,
		"2001:DB8::0001", "legacy", "admin"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	if err := NormalizeBlockedIPs(ctx, db); err != nil {
		t.Fatalf("NormalizeBlockedIPs() error = %v", err)
	}

	var ip string
	if err := db.QueryRowContext(ctx, `SELECT ip_address FROM blocked_ips`).Scan(&ip); err != nil {
		t.Fatalf("query: %v", err)
	}
	if want := "2001:db8::1"; ip != want {
		t.Errorf("ip_address after normalization = %q, want %q", ip, want)
	}
}

func TestNormalizeBlockedIPs_Idempotent(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)`,
		"203.0.113.5", "seed", "admin"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	if err := NormalizeBlockedIPs(ctx, db); err != nil {
		t.Fatalf("first NormalizeBlockedIPs() error = %v", err)
	}
	if err := NormalizeBlockedIPs(ctx, db); err != nil {
		t.Fatalf("second NormalizeBlockedIPs() error = %v", err)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM blocked_ips`).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 1 {
		t.Errorf("row count after two normalization runs = %d, want 1", count)
	}
}

func TestNormalizeBlockedIPs_MergesDuplicates(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	// Two rows that canonicalize to the same value, inserted in a known
	// order so we can assert the oldest (lowest id) one survives.
	if _, err := db.ExecContext(ctx, `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)`,
		"2001:db8::1", "oldest", "admin"); err != nil {
		t.Fatalf("seed insert 1: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)`,
		"2001:DB8:0000:0000:0000:0000:0000:0001", "newer-duplicate", "admin"); err != nil {
		t.Fatalf("seed insert 2: %v", err)
	}

	if err := NormalizeBlockedIPs(ctx, db); err != nil {
		t.Fatalf("NormalizeBlockedIPs() error = %v", err)
	}

	rows, err := db.QueryContext(ctx, `SELECT ip_address, reason FROM blocked_ips`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var got []struct{ ip, reason string }
	for rows.Next() {
		var ip, reason string
		if err := rows.Scan(&ip, &reason); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, struct{ ip, reason string }{ip, reason})
	}

	if len(got) != 1 {
		t.Fatalf("got %d rows after merge, want 1: %+v", len(got), got)
	}
	if got[0].ip != "2001:db8::1" {
		t.Errorf("surviving row ip = %q, want %q", got[0].ip, "2001:db8::1")
	}
	if got[0].reason != "oldest" {
		t.Errorf("surviving row reason = %q, want %q (the oldest/first row should be kept)", got[0].reason, "oldest")
	}
}

func TestNormalizeBlockedIPs_LeavesUnparsableRowsAlone(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)`,
		"not-an-ip-or-cidr", "garbage", "admin"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	if err := NormalizeBlockedIPs(ctx, db); err != nil {
		t.Fatalf("NormalizeBlockedIPs() error = %v", err)
	}

	var ip string
	if err := db.QueryRowContext(ctx, `SELECT ip_address FROM blocked_ips`).Scan(&ip); err != nil {
		t.Fatalf("query: %v", err)
	}
	if ip != "not-an-ip-or-cidr" {
		t.Errorf("ip_address = %q, want unchanged %q", ip, "not-an-ip-or-cidr")
	}
}

func TestNormalizeBlockedIPs_EmptyTable(t *testing.T) {
	db := setupTestDB(t)
	if err := NormalizeBlockedIPs(context.Background(), db); err != nil {
		t.Fatalf("NormalizeBlockedIPs() on empty table error = %v", err)
	}
}

// TestNormalizeBlockedIPs_LegacyBroadCIDR_LeftAloneAndWarned is a
// code-review follow-up (T43): a legacy CIDR row broader than the current
// bound (e.g. "10.0.0.0/4") must be left completely untouched by
// normalization -- it can't canonicalize, so rewriting or deleting it would
// risk silently un-enforcing a block the operator still wants -- and must
// produce a specific Warn log calling it out for review, distinct from the
// generic "doesn't parse at all" warning.
func TestNormalizeBlockedIPs_LegacyBroadCIDR_LeftAloneAndWarned(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)`,
		"10.0.0.0/4", "legacy broad block", "admin"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	var logBuf bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(prevLogger)

	if err := NormalizeBlockedIPs(ctx, db); err != nil {
		t.Fatalf("NormalizeBlockedIPs() error = %v", err)
	}

	var ip string
	if err := db.QueryRowContext(ctx, `SELECT ip_address FROM blocked_ips`).Scan(&ip); err != nil {
		t.Fatalf("query: %v", err)
	}
	if ip != "10.0.0.0/4" {
		t.Errorf("legacy broad CIDR row was modified: ip_address = %q, want unchanged %q", ip, "10.0.0.0/4")
	}

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "legacy CIDR broader than") {
		t.Errorf("expected a Warn log specifically about the legacy broad CIDR row, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "10.0.0.0/4") {
		t.Errorf("expected the Warn log to name the offending value, got:\n%s", logOutput)
	}
}
