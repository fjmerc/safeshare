package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/utils"
)

// upgradeCrashPoint identifies a point inside commitFormatUpgrade's sequence
// at which a test can simulate the process dying (by returning
// errSimulatedCrash immediately after that step instead of continuing), so
// tests can assert the crash-safety invariant documented on
// commitFormatUpgrade actually holds at every intermediate state. Production
// callers always pass crashNone.
type upgradeCrashPoint int

const (
	crashNone upgradeCrashPoint = iota
	// crashAfterTempWritten simulates a crash after the new-format temp
	// file is fully written, fsynced, and the containing directory fsynced
	// — but before the DB row is touched. Expected post-crash state: old
	// file + old DB row, both untouched; the temp file is orphaned garbage.
	crashAfterTempWritten
	// crashAfterDBCommit simulates a crash after the DB transaction
	// committed the new enc_file_id (and sha256_hash, if newly computed) —
	// but before the rename. Expected post-crash state: DB row already
	// describes the NEW format, but the file under finalPath is still the
	// OLD format, unchanged. This is the load-bearing case: see
	// commitFormatUpgrade's doc comment for why reads against that state
	// remain correct.
	crashAfterDBCommit
	// crashAfterRename simulates a crash after the rename succeeded but
	// before the final post-rename directory fsync. Expected post-crash
	// state: fully upgraded (new file at finalPath, DB row matches); the
	// missing fsync only affects durability against a hard power loss, not
	// process-crash correctness.
	crashAfterRename
)

// errSimulatedCrash is returned by commitFormatUpgrade when a test-injected
// crashPoint is reached, standing in for "the process died right here."
var errSimulatedCrash = errors.New("simulated crash for testing")

// errFinalPathVanishedDuringCommit is returned by commitFormatUpgrade when
// finalPath no longer exists immediately before the rename step — the row
// (and, typically, its file) were deleted concurrently, most plausibly by
// the background expiry-cleanup sweep, in the window between the DB commit
// and this check. This is not a failure: the file's row is already gone,
// so there is nothing left to upgrade. Callers must treat this the same as
// "not applicable" (like an already-SFSE2 or plaintext file), never as a
// failure to retry, and never rename the temp file in — see
// commitFormatUpgrade's doc comment for how the leftover temp file is
// cleaned up.
var errFinalPathVanishedDuringCommit = errors.New("final path vanished before rename (row+file deleted concurrently, e.g. by expiry cleanup)")

// commitFormatUpgrade performs the crash-safe swap from an old-format file
// at finalPath to an already-fully-written new-format file at tempPath
// (SFSE2, for every caller in this package today), updating the files row's
// enc_file_id — and sha256_hash, when updateHash is true — to match.
//
// # Ordering, and why it is safe at every step
//
//  1. fsync tempPath's contents, close it, then fsync uploadsDir — makes the
//     new file's bytes (and its directory entry under the temp name)
//     durable before anything references them.
//  2. Commit a single DB transaction: UPDATE files SET enc_file_id = ?
//     [, sha256_hash = ?] WHERE id = ? AND stored_filename = ?. SQLite
//     transactions are atomic, so this step either fully happens or not at
//     all — there is no "partially committed" state to worry about.
//  3. os.Rename(tempPath, finalPath) — a single atomic syscall on POSIX.
//     Any reader with an already-open fd on the old inode (a download in
//     flight) keeps reading the old bytes to completion; a reader that
//     opens finalPath afterward gets the new file. Both are correct reads.
//  4. fsync uploadsDir again, for durability of the rename's directory-entry
//     update against a hard power loss (best-effort: logged, not fatal, if
//     it fails — the rename itself already succeeded and is what matters
//     for process-crash correctness).
//
// # Why DB-commit-before-rename (not the reverse) is the load-bearing choice
//
// Consider a crash between step 2 and step 3 (crashAfterDBCommit): the files
// row now names the NEW enc_file_id (and possibly a freshly-computed
// sha256_hash), but the file under finalPath is still the OLD-format bytes,
// completely untouched. A concurrent or resumed download opens finalPath,
// stats it, and asks utils.OpenSFSEReader to decrypt it using the row's
// (new) enc_file_id — but OpenSFSEReader determines the SFSE1-vs-SFSE2
// branch purely from the on-disk header's version byte, and the SFSE1
// branch never reads encFileID at all (SFSE1 predates per-chunk AAD
// entirely — see ADR-011). So a still-SFSE1 file on disk is decrypted
// correctly regardless of what enc_file_id the row now claims.
// files.file_size is unchanged by a format upgrade (same plaintext,
// re-encoded in a new container), and sha256_hash — even when this call
// just filled it in for the first time — is a hash of that same unchanged
// plaintext, so it still verifies correctly against the still-old file.
// The window is therefore safe to read through, AND idempotently
// resumable: a rerun that finds the row already updated but the file still
// old-format simply redoes the encrypt-and-rename (callers key their
// "already upgraded" skip check off the on-disk format via
// utils.ClassifyStoredFile/PeekSFSEVersion, not off the DB row, precisely
// so this resumes correctly).
//
// The reverse order (rename first, then commit) is NOT safe: a crash
// between them would leave finalPath already holding new-format bytes while
// the row still names the OLD (for a legacy/SFSE1->SFSE2 upgrade, often
// nil) enc_file_id. A reader opening the file in that window would ask
// OpenSFSEReader to authenticate real SFSE2 AAD chunks against a stale or
// missing enc_file_id, which fails closed (a clean decrypt error, never
// corrupt output) — but still means every download of that file hard-fails
// until an operator re-runs the tool, an entirely avoidable outage this
// ordering sidesteps.
//
// # Residual risk (documented, not eliminated)
//
// A request that read the OLD files row *before* step 2 committed, but does
// not actually os.Open the file until *after* step 3's rename, will hand
// OpenSFSEReader a stale enc_file_id against the already-upgraded file and
// get a clean decrypt error (never corrupt output — OpenSFSEReader's
// length/AAD checks are fail-closed by construction). This window is a
// handful of syscalls wide (a DB commit immediately followed by a rename)
// against a request's full round trip through the handler's own DB read and
// file open, so it is vanishingly unlikely in practice. This tool also
// takes a process-local flock (see acquireProcessLock) so two instances of
// it can't race each other, but that lock does NOT protect against the live
// SafeShare server process racing a migration — see the README and the
// tool's own startup log line for the operational recommendation (run
// during a maintenance window, or accept the narrow, fail-closed window
// above).
//
// A second, distinct residual risk (database-review finding): the
// background expiry-cleanup worker (runPartialUploadCleanup ->
// database.DeleteExpiredFiles, internal/utils/cleanup.go) runs
// independently of this tool and deletes both a files row AND its on-disk
// file together once expires_at has passed. If that sweep deletes file X's
// row+file in the narrow window between this function's DB commit (step 2)
// and its rename (step 3), finalPath no longer exists when the rename
// runs — os.Rename would then simply recreate a file at finalPath with no
// matching DB row at all: a genuine orphan, indistinguishable from any
// other stale file. This is handled two ways: (1) immediately before the
// rename, this function re-stats finalPath and, if it's already gone,
// skips the rename entirely and returns errFinalPathVanishedDuringCommit
// instead. Both current callers (upgradeOneFileToSFSE2, migrateEncryption)
// treat that sentinel as "not applicable" (not a failure to retry) and
// immediately os.Remove the now-pointless temp file themselves — so in
// practice this path leaves nothing behind at all. (2) As a backstop for
// the unlikely case that immediate cleanup is itself interrupted (a crash
// between the sentinel return and the os.Remove call), the existing
// general-purpose orphan sweep, utils.CleanupOrphanedFiles (also wired into
// runPartialUploadCleanup, same worker), would still catch the leftover
// temp file on its normal schedule regardless of what it's named — it
// compares every file actually present in uploadsDir against the current
// set of DB stored_filenames and removes anything unmatched once past its
// grace period. The stat-then-rename check narrows the window (down to the
// gap between the stat and the rename syscalls themselves) rather than
// eliminating it — an expiry delete landing in that final, much smaller gap
// is a plain, already-existing race between concurrent deletes and renames
// in POSIX, not something specific to this tool, and any orphan it could
// still produce is caught by the same sweep regardless.
//
// Precondition: tempPath's contents must already be durable on disk before
// this is called — the caller must have called Sync() on the same *os.File
// it wrote tempPath through, and treated any error from that Sync as fatal,
// before Close()ing it and calling this function. (This function used to
// reopen tempPath and Sync it itself; that's redundant work through a fresh
// fd when the writer's own fd can — and now does — do it directly, and a
// Sync error caught there is more actionable than one caught here after the
// writer has already moved on.) This function only needs to fsync the
// directory, which is what makes the temp file's directory-entry (its
// *name* existing at all) durable — fsyncing a file's own contents never
// covers that.
func commitFormatUpgrade(db *sql.DB, uploadsDir, finalPath, tempPath string, fileID int64, storedFilename string, newEncFileID []byte, newSHA256 string, updateHash bool, crash upgradeCrashPoint) error {
	if err := fsyncDir(uploadsDir); err != nil {
		return fmt.Errorf("fsync uploads dir (pre-commit): %w", err)
	}
	if crash == crashAfterTempWritten {
		return errSimulatedCrash
	}

	if err := updateEncFileIDAndHash(db, fileID, storedFilename, newEncFileID, newSHA256, updateHash); err != nil {
		return fmt.Errorf("commit DB row: %w", err)
	}
	if crash == crashAfterDBCommit {
		return errSimulatedCrash
	}

	// Narrow (not eliminate) the expiry-cleanup-race window documented
	// above: re-check that finalPath still exists immediately before the
	// rename. If it's already gone — the row+file were deleted concurrently
	// while we held no lock preventing it — renaming our temp file in now
	// would create a genuine orphan (a file with no matching DB row at
	// all). Skip the rename; the temp file is left for the existing
	// orphan sweep (utils.CleanupOrphanedFiles) to reclaim on its own
	// schedule, same as any other stale file.
	if _, statErr := os.Lstat(finalPath); errors.Is(statErr, fs.ErrNotExist) {
		return errFinalPathVanishedDuringCommit
	}

	if err := os.Rename(tempPath, finalPath); err != nil {
		return fmt.Errorf("rename %s -> %s (DB already committed the new enc_file_id — rerun this tool to retry; %s is still safely readable in its old format meanwhile, see commitFormatUpgrade's doc comment): %w",
			tempPath, finalPath, finalPath, err)
	}
	if crash == crashAfterRename {
		return errSimulatedCrash
	}

	if err := fsyncDir(uploadsDir); err != nil {
		// Non-fatal: the rename itself already succeeded, which is what
		// matters for process-crash correctness. This second fsync only
		// tightens durability against a hard power loss.
		slog.Warn("fsync uploads dir after rename failed (rename itself succeeded)", "dir", uploadsDir, "error", err)
	}
	return nil
}

// preserveFileOwnership makes tempPath match origInfo's permission bits,
// and — when this process is running as root — its owner/group too, before
// the crash-safe commit renames it into place.
//
// Without this, a migrated file silently ends up 0600 root:root whenever
// this tool runs as a different user than the one that originally wrote the
// file — most plausibly this tool run directly on the Docker host (or via a
// root SSH/console session) rather than via `docker exec` into the running
// container as its non-root user (see cmd/migrate-encryption/README.md's
// "Docker Usage" section). The live server (uid 1000 in the shipped image)
// then gets EACCES reading the file back, and every future download of it
// 500s — a self-inflicted, entirely avoidable outage.
//
// Chown is skipped (not an error) when this process isn't running as root:
// an unprivileged process can never chown a file to a different owner
// anyway (EPERM), and in that case tempPath is already owned by this
// process's own uid/gid — the same identity every other file this process
// writes gets — which is correct behavior, not a gap.
func preserveFileOwnership(tempPath string, origInfo os.FileInfo) error {
	if err := os.Chmod(tempPath, origInfo.Mode().Perm()); err != nil {
		return fmt.Errorf("chmod %s to match original mode %s: %w", tempPath, origInfo.Mode().Perm(), err)
	}
	if os.Geteuid() != 0 {
		return nil
	}
	stat, ok := origInfo.Sys().(*syscall.Stat_t)
	if !ok {
		// Not running on a platform that exposes syscall.Stat_t (never
		// happens for this codebase's Linux-only deployment target, but
		// fail safe rather than panic on the type assertion) — the
		// permission bits are already fixed above, which is the more
		// important half of this fix in practice.
		return nil
	}
	if err := os.Chown(tempPath, int(stat.Uid), int(stat.Gid)); err != nil {
		return fmt.Errorf("chown %s to match original owner %d:%d: %w", tempPath, stat.Uid, stat.Gid, err)
	}
	return nil
}

// fsyncDir opens dir and fsyncs it, which is what makes a preceding file
// creation or rename's directory-entry update durable against a crash —
// fsyncing the file itself only guarantees the file's own contents/metadata,
// not that the directory entry pointing at it survives a crash.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// updateEncFileIDAndHash commits the enc_file_id (and, when updateHash is
// true, sha256_hash) update in its own short transaction. The
// stored_filename equality check is a defense-in-depth guard against
// updating the wrong row if a file's stored_filename were ever reused
// (never happens in practice — stored filenames are UUIDs — but costs
// nothing to check).
func updateEncFileIDAndHash(db *sql.DB, fileID int64, storedFilename string, encFileID []byte, sha256Hash string, updateHash bool) error {
	tx, err := database.BeginImmediateTx(db)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && rbErr != sql.ErrTxDone {
			slog.Warn("rollback failed", "error", rbErr)
		}
	}()

	var res sql.Result
	if updateHash {
		res, err = tx.Exec(`UPDATE files SET enc_file_id = ?, sha256_hash = ? WHERE id = ? AND stored_filename = ?`,
			encFileID, sha256Hash, fileID, storedFilename)
	} else {
		res, err = tx.Exec(`UPDATE files SET enc_file_id = ? WHERE id = ? AND stored_filename = ?`,
			encFileID, fileID, storedFilename)
	}
	if err != nil {
		return fmt.Errorf("update files row: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("no matching files row (id=%d stored_filename=%q) — row changed underneath this run", fileID, storedFilename)
	}
	return tx.Commit()
}

// acquireProcessLock takes an exclusive, non-blocking flock on a lock file
// inside uploadsDir, so two invocations of this tool can't run a mutating
// pass over the same files concurrently and race each other's
// temp-file/DB-update/rename sequences (a real risk: both would pick the
// same finalPath, and the second's os.Create(tempPath) or rename could
// interleave with the first's).
//
// This does NOT protect against the live SafeShare server process — a
// distributed DB-row lock would only ever be advisory against a server that
// doesn't check it, and this tool intentionally avoids adding a check the
// server would have to honor for a one-off admin operation. See
// commitFormatUpgrade's doc comment for the (narrow, fail-closed) residual
// window against the running server, and run this during a maintenance
// window when that window must be fully eliminated.
func acquireProcessLock(uploadsDir string) (unlock func(), err error) {
	path := filepath.Join(uploadsDir, ".safeshare-migrate-encryption.lock")
	// 0644, not 0600: this lock file is created once and then reused by
	// every future invocation of this tool, potentially as a different
	// user each time (e.g. once as root directly on the host, later via
	// `docker exec` as the container's non-root user). 0600 from a root-run
	// would make a later non-root run's O_RDWR open fail outright. When
	// running as root, additionally chown it to match uploadsDir's own
	// owner, so a later non-root run against the same directory can open
	// (and flock) it at all.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	if os.Geteuid() == 0 {
		if dirInfo, statErr := os.Stat(uploadsDir); statErr == nil {
			if stat, ok := dirInfo.Sys().(*syscall.Stat_t); ok {
				if chownErr := os.Chown(path, int(stat.Uid), int(stat.Gid)); chownErr != nil {
					slog.Warn("failed to chown lock file to uploads dir owner", "path", path, "error", chownErr)
				}
			}
		}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another migrate-encryption process already holds the lock on %s — refusing to run concurrently against the same uploads directory: %w", uploadsDir, err)
	}
	return func() {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
			slog.Warn("failed to release process lock", "error", err)
		}
		f.Close()
	}, nil
}

// upgradeOneFileToSFSE2 upgrades a single SFSE1 file to SFSE2 in place.
// Returns applicable=false (no error) when row's on-disk file is not SFSE1
// — already SFSE2, plaintext, legacy, or unclassifiable — since none of
// those are this operation's job (an unclassifiable/legacy file is left for
// --verify / the ordinary migration pass to report or handle). dryRun
// reports what would happen without writing anything. crash is
// crashNone in production; tests pass the other values to verify
// commitFormatUpgrade's crash-safety invariant.
func upgradeOneFileToSFSE2(db *sql.DB, uploadsDir string, row verifyFileRow, encryptionKey string, dryRun bool, crash upgradeCrashPoint) (applicable bool, err error) {
	if err := utils.ValidateStoredFilename(row.StoredFilename); err != nil {
		return false, fmt.Errorf("invalid stored_filename %q: %w", row.StoredFilename, err)
	}
	finalPath := filepath.Join(uploadsDir, row.StoredFilename)

	f, err := os.Open(finalPath)
	if err != nil {
		return false, fmt.Errorf("open: %w", err)
	}
	fi, statErr := f.Stat()
	if statErr != nil {
		f.Close()
		return false, fmt.Errorf("stat: %w", statErr)
	}

	format, classifyErr := utils.ClassifyStoredFile(f, fi, row.FileSize, true)
	if classifyErr != nil {
		f.Close()
		return false, fmt.Errorf("classify: %w", classifyErr)
	}
	if format != utils.FormatSFSE1 {
		f.Close()
		return false, nil
	}
	if dryRun {
		f.Close()
		return true, nil
	}

	// Stream it: decrypt the SFSE1 file through the verified reader
	// (utils.OpenSFSEReader — same structural validation and, when
	// row.SHA256Hash is set, whole-file hash verification that a normal
	// claim download gets) and re-encrypt straight into a temp file in the
	// same directory. needHash wraps the reader in a TeeReader so a
	// previously-empty sha256_hash gets computed as a side effect of this
	// single pass, instead of a second read.
	reader, err := utils.OpenSFSEReader(f, fi, encryptionKey, nil, row.FileSize, row.SHA256Hash)
	if err != nil {
		f.Close()
		return false, fmt.Errorf("open SFSE1 reader: %w", err)
	}

	needHash := row.SHA256Hash == ""
	var hasher hash.Hash
	var src io.Reader = reader
	if needHash {
		hasher = sha256.New()
		src = io.TeeReader(reader, hasher)
	}

	newEncFileID, err := utils.GenerateEncFileID()
	if err != nil {
		reader.Close()
		f.Close()
		return false, fmt.Errorf("generate enc_file_id: %w", err)
	}

	tempPath := finalPath + ".sfse2upgrade.tmp"
	// Remove any stale temp file left behind by a prior crashed run before
	// the O_EXCL create below — otherwise a crash between a previous run's
	// os.Create and its eventual rename/cleanup permanently blocks every
	// later rerun with EEXIST. Safe to do unconditionally: this whole
	// function only ever runs while runUpgradeFormat/migrateEncryption hold
	// the process-local flock (acquireProcessLock), so nothing else is
	// concurrently writing this exact temp path.
	if err := os.Remove(tempPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		reader.Close()
		f.Close()
		return false, fmt.Errorf("remove stale temp file %s: %w", tempPath, err)
	}
	tempFile, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		reader.Close()
		f.Close()
		return false, fmt.Errorf("create temp file %s: %w", tempPath, err)
	}
	var tempOK bool
	defer func() {
		if !tempOK {
			os.Remove(tempPath)
		}
	}()

	encErr := utils.EncryptFileStreamingV2FromReader(tempFile, src, encryptionKey, newEncFileID, row.FileSize)
	var syncErr error
	if encErr == nil {
		// Sync via the same fd we wrote through, before Close — catches a
		// writeback error here, attributable to this file, rather than
		// letting it surface (or not, on some filesystems/kernels) later
		// through an unrelated fd. commitFormatUpgrade now assumes this
		// already happened; see its doc comment.
		syncErr = tempFile.Sync()
	}
	closeErr := tempFile.Close()
	reader.Close()
	f.Close()
	if encErr != nil {
		// Propagates SFSE1 integrity failures (utils.ErrSFSEHashMismatch /
		// ErrSFSEChunkAuthFailed / ErrSFSE2IntegrityCheckFailed, all wrapped
		// through io.ReadFull's error return inside
		// EncryptFileStreamingV2FromReader) exactly as a normal claim
		// download's decrypt path would surface them — nothing is
		// committed or renamed when this happens.
		return false, fmt.Errorf("re-encrypt to SFSE2: %w", encErr)
	}
	if syncErr != nil {
		return false, fmt.Errorf("fsync temp file: %w", syncErr)
	}
	if closeErr != nil {
		return false, fmt.Errorf("close temp file: %w", closeErr)
	}

	// Preserve the original file's mode (and, when running as root, its
	// owner/group) on the re-encrypted temp file before it gets renamed
	// into place — see preserveFileOwnership's doc comment for why this
	// matters (a mismatched owner turns into every future download of this
	// file 500ing with EACCES once it's live).
	if err := preserveFileOwnership(tempPath, fi); err != nil {
		return false, fmt.Errorf("preserve file ownership: %w", err)
	}

	newHash := row.SHA256Hash
	if needHash {
		newHash = hex.EncodeToString(hasher.Sum(nil))
	}

	if err := commitFormatUpgrade(db, uploadsDir, finalPath, tempPath, row.ID, row.StoredFilename, newEncFileID, newHash, needHash, crash); err != nil {
		if errors.Is(err, errFinalPathVanishedDuringCommit) {
			// Not a failure: the row (and its file) were deleted
			// concurrently — most plausibly by expiry cleanup — so there is
			// nothing left to upgrade. The deferred cleanup above removes
			// the now-pointless temp file immediately (tempOK stays
			// false); see commitFormatUpgrade's doc comment for the
			// orphan-sweep backstop if that immediate cleanup itself were
			// ever interrupted.
			return false, nil
		}
		return false, err
	}
	tempOK = true
	return true, nil
}

// upgradeReport summarizes a --upgrade-format run.
type upgradeReport struct {
	TotalRows        int
	Upgraded         int // non-dry-run: files actually re-sealed to SFSE2
	DryRunCandidates int // dry-run: files that would have been re-sealed
	NotApplicable    int // already SFSE2, plaintext, legacy, or missing/unclassifiable (left to --verify to report in detail)
	Failed           int
}

// runUpgradeFormat re-seals every SFSE1 file in db to SFSE2 (master finding
// #10). Requires a real (non-empty, valid) encryptionKey — SFSE1 files
// cannot be identified or read without one. Takes acquireProcessLock for
// the duration of the run (skipped for --dry-run, which writes nothing).
func runUpgradeFormat(db *sql.DB, uploadsDir, encryptionKey string, dryRun bool) (*upgradeReport, error) {
	if !utils.IsEncryptionEnabled(encryptionKey) {
		return nil, fmt.Errorf("--upgrade-format requires a valid --enckey")
	}

	if !dryRun {
		unlock, err := acquireProcessLock(uploadsDir)
		if err != nil {
			return nil, err
		}
		defer unlock()
	}

	rows, err := listFilesForVerify(db, true)
	if err != nil {
		return nil, err
	}

	report := &upgradeReport{TotalRows: len(rows)}
	for _, row := range rows {
		if err := utils.ValidateStoredFilename(row.StoredFilename); err != nil {
			// A row with an unsafe stored_filename should never exist in
			// practice (stored filenames are always UUIDs this codebase
			// generates itself), but fail this row rather than build a
			// path from it, exactly as upgradeOneFileToSFSE2 itself would
			// — checked here too so the os.Stat below never touches disk
			// with an unvalidated name either.
			report.Failed++
			slog.Error("upgrade-format: invalid stored_filename, refusing to touch disk",
				"claim_code", redactClaimCode(row.ClaimCode),
				"stored_filename", row.StoredFilename,
				"error", err,
			)
			continue
		}
		path := filepath.Join(uploadsDir, row.StoredFilename)
		if _, statErr := os.Stat(path); statErr != nil {
			// Missing files are --verify's concern to report in detail;
			// silently not-applicable here.
			report.NotApplicable++
			continue
		}

		applicable, err := upgradeOneFileToSFSE2(db, uploadsDir, row, encryptionKey, dryRun, crashNone)
		if err != nil {
			report.Failed++
			slog.Error("upgrade-format: file failed",
				"claim_code", redactClaimCode(row.ClaimCode),
				"stored_filename", row.StoredFilename,
				"error", err,
			)
			continue
		}
		if !applicable {
			report.NotApplicable++
			continue
		}
		if dryRun {
			report.DryRunCandidates++
		} else {
			report.Upgraded++
			slog.Info("upgrade-format: re-sealed SFSE1 -> SFSE2",
				"claim_code", redactClaimCode(row.ClaimCode),
				"stored_filename", row.StoredFilename,
			)
		}
	}
	return report, nil
}

// printUpgradeReport writes a human-readable summary of report to w.
func printUpgradeReport(w io.Writer, report *upgradeReport, dryRun bool) {
	fmt.Fprintln(w, "\n=== Upgrade-Format Summary (SFSE1 -> SFSE2) ===")
	fmt.Fprintf(w, "Total files checked: %d\n", report.TotalRows)
	if dryRun {
		fmt.Fprintf(w, "Would upgrade:       %d\n", report.DryRunCandidates)
	} else {
		fmt.Fprintf(w, "Upgraded:            %d\n", report.Upgraded)
	}
	fmt.Fprintf(w, "Not applicable:      %d (already SFSE2, plaintext, legacy, or missing — see --verify for a detailed breakdown)\n", report.NotApplicable)
	fmt.Fprintf(w, "Failed:              %d\n", report.Failed)
}
