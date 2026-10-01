package database

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRequireLocalBackends verifies the CLI admin tools' (cmd/import-file,
// cmd/migrate-encryption) guard against running against a deployment
// actually configured for PostgreSQL and/or S3, which they cannot read or
// write correctly — they only ever operate on a local SQLite file and local
// uploads directory.
func TestRequireLocalBackends(t *testing.T) {
	tests := []struct {
		name        string
		databaseTyp string
		storageTyp  string
		wantErr     bool
		wantSubstr  string
	}{
		{name: "both unset (defaults)", wantErr: false},
		{name: "explicit sqlite + filesystem", databaseTyp: "sqlite", storageTyp: "filesystem", wantErr: false},
		{name: "postgresql", databaseTyp: "postgresql", wantErr: true, wantSubstr: "PostgreSQL"},
		{name: "s3", storageTyp: "s3", wantErr: true, wantSubstr: "S3"},
		{name: "both non-default", databaseTyp: "postgresql", storageTyp: "s3", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DATABASE_TYPE", tt.databaseTyp)
			t.Setenv("STORAGE_TYPE", tt.storageTyp)

			err := RequireLocalBackends()
			if tt.wantErr && err == nil {
				t.Fatal("RequireLocalBackends() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("RequireLocalBackends() = %v, want nil", err)
			}
			if tt.wantSubstr != "" && err != nil && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error %q does not mention %q", err.Error(), tt.wantSubstr)
			}
		})
	}
}

// TestOpenForCLI_Success verifies OpenForCLI opens an existing,
// server-initialized database successfully and the connection is usable.
// TestOpenForCLI_MissingFile is the regression test for the LOW finding
// that OpenForCLI would otherwise silently create a new, empty database at
// a mistyped --db path (sql.Open + the sqlite driver don't touch the file
// until the first query) instead of failing clearly up front.
func TestOpenForCLI_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "does-not-exist.db")

	if _, err := OpenForCLI(dbPath); err == nil {
		t.Fatal("OpenForCLI succeeded against a nonexistent path, want error")
	}
	if _, statErr := os.Stat(dbPath); !os.IsNotExist(statErr) {
		t.Errorf("OpenForCLI created a file at the mistyped path (stat err = %v), want none created", statErr)
	}
}

func TestOpenForCLI_Success(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	setup, err := Initialize(dbPath)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	setup.Close()

	db, err := OpenForCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenForCLI: %v", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM files").Scan(&count); err != nil {
		t.Fatalf("query files table: %v", err)
	}
}

// TestOpenForCLI_RefusesNonSafeShareDB verifies OpenForCLI fails clearly
// (rather than letting the first real query fail obliquely) when pointed at
// a SQLite file that isn't a SafeShare database — no `files` table.
func TestOpenForCLI_RefusesNonSafeShareDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "not-safeshare.db")

	// Create a valid-but-unrelated SQLite file.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.Exec("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create unrelated table: %v", err)
	}
	raw.Close()

	db, err := OpenForCLI(dbPath)
	if err == nil {
		db.Close()
		t.Fatal("OpenForCLI succeeded against a non-SafeShare database, want error")
	}
}

// TestOpenForCLI_WaitsOnBusyLock is the regression test for the
// code-review/database-review finding that the CLI tools previously opened
// SQLite with a bare sql.Open — no busy_timeout (defaults to 0) and no
// _txlock=immediate — so any write that conflicted with a lock held by the
// live server failed immediately with SQLITE_BUSY instead of waiting
// briefly, as every other write path in this codebase does via
// BeginImmediateTx + the connection-hook busy_timeout pragma.
//
// It holds an IMMEDIATE-lock transaction open on one OpenForCLI connection
// for ~1s (simulating a concurrent write from the live server), while a
// second OpenForCLI connection — representing the CLI tool — starts its own
// BeginImmediateTx + UPDATE + Commit shortly after the first lock is
// acquired. The second connection must wait for the first to release the
// lock and then succeed, not fail immediately.
func TestOpenForCLI_WaitsOnBusyLock(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	setup, err := Initialize(dbPath)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	fileID := seedOneFile(t, setup)
	setup.Close()

	holder, err := OpenForCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenForCLI (holder): %v", err)
	}
	defer holder.Close()

	cliConn, err := OpenForCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenForCLI (cli): %v", err)
	}
	defer cliConn.Close()

	const holdDuration = 1 * time.Second
	lockAcquired := make(chan struct{})
	releaseDone := make(chan error, 1)

	go func() {
		ctx := context.Background()
		tx, err := BeginImmediateTxContext(ctx, holder)
		if err != nil {
			close(lockAcquired)
			releaseDone <- err
			return
		}
		// Touch a row so this transaction genuinely holds a write lock, not
		// just a read-only IMMEDIATE reservation.
		if _, err := tx.Exec(`UPDATE files SET download_count = download_count + 1 WHERE id = ?`, fileID); err != nil {
			close(lockAcquired)
			tx.Rollback()
			releaseDone <- err
			return
		}
		close(lockAcquired)
		time.Sleep(holdDuration)
		releaseDone <- tx.Commit()
	}()

	<-lockAcquired

	start := time.Now()
	ctx := context.Background()
	tx, err := BeginImmediateTxContext(ctx, cliConn)
	if err != nil {
		t.Fatalf("CLI connection BeginImmediateTx failed instead of waiting: %v", err)
	}
	if _, err := tx.Exec(`UPDATE files SET download_count = download_count + 1 WHERE id = ?`, fileID); err != nil {
		tx.Rollback()
		t.Fatalf("CLI connection UPDATE failed instead of waiting: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("CLI connection Commit failed: %v", err)
	}
	elapsed := time.Since(start)

	if err := <-releaseDone; err != nil {
		t.Fatalf("holder transaction failed: %v", err)
	}

	// The CLI write must have actually waited for the ~1s-held lock, not
	// raced in before it or failed instantly — a generous lower bound
	// avoids flakiness from scheduling jitter while still clearly
	// distinguishing "waited" from "failed immediately" or "wasn't really
	// contended".
	if elapsed < 400*time.Millisecond {
		t.Errorf("CLI write completed in %v, want >= ~%v (suggests it didn't actually wait on the held lock — busy_timeout not effective)", elapsed, holdDuration)
	}
}

// TestOpenForCLI_ContrastBareOpenFailsImmediately is a companion negative
// control: it reproduces the exact pre-fix behavior (a bare sql.Open, no
// busy_timeout, no _txlock=immediate) under the same contention and asserts
// it fails fast instead of waiting — demonstrating what OpenForCLI actually
// fixes, not just that OpenForCLI itself happens to work.
func TestOpenForCLI_ContrastBareOpenFailsImmediately(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	setup, err := Initialize(dbPath)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	fileID := seedOneFile(t, setup)
	setup.Close()

	holder, err := OpenForCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenForCLI (holder): %v", err)
	}
	defer holder.Close()

	// The old call pattern: bare sql.Open, no DSN parameters, no connection
	// hook pragmas (registerConnectionHook was never called by this
	// connection's DSN-less path in the pre-fix CLI tools — but since the
	// hook is process-global and OpenForCLI above already registered it in
	// this test binary, exercise the DSN difference specifically, which is
	// what actually matters: _txlock=immediate absent, and, in a fresh
	// process that never called OpenForCLI/Initialize first, no
	// busy_timeout pragma either).
	bare, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer bare.Close()
	// Explicitly disable any busy wait this connection might otherwise
	// inherit, to isolate exactly the DSN/pragma difference OpenForCLI
	// fixes rather than depending on hook-registration ordering between
	// tests in this package.
	if _, err := bare.Exec("PRAGMA busy_timeout = 0"); err != nil {
		t.Fatalf("PRAGMA busy_timeout=0: %v", err)
	}

	lockAcquired := make(chan struct{})
	releaseDone := make(chan error, 1)
	go func() {
		ctx := context.Background()
		tx, err := BeginImmediateTxContext(ctx, holder)
		if err != nil {
			close(lockAcquired)
			releaseDone <- err
			return
		}
		if _, err := tx.Exec(`UPDATE files SET download_count = download_count + 1 WHERE id = ?`, fileID); err != nil {
			close(lockAcquired)
			tx.Rollback()
			releaseDone <- err
			return
		}
		close(lockAcquired)
		time.Sleep(1 * time.Second)
		releaseDone <- tx.Commit()
	}()

	<-lockAcquired

	// A plain, deferred (not IMMEDIATE) transaction under a bare sql.Open
	// with busy_timeout=0 must fail fast (SQLITE_BUSY) rather than wait —
	// this is exactly the pre-fix behavior the finding described.
	_, execErr := bare.Exec(`UPDATE files SET download_count = download_count + 1 WHERE id = ?`, fileID)
	if execErr == nil {
		t.Error("bare sql.Open write succeeded without waiting — expected it to fail fast under contention (busy_timeout=0), demonstrating why OpenForCLI is needed")
	}

	<-releaseDone
}

// seedOneFile inserts a minimal files row and returns its id, for tests
// that need a real row to UPDATE under lock contention.
func seedOneFile(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"lock-test-claim", "f.txt", "f.txt", 10, "text/plain", time.Now().Add(time.Hour).Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("seed file row: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}
