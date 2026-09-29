package main

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

const upgradeTestKey = "1111111111111111111111111111111111111111111111111111111111111111"

// newUpgradeFixture writes one SFSE1-encrypted file to uploadsDir and its
// matching files row (no enc_file_id, no sha256_hash — exactly what a
// pre-SFSE2 row looks like) to db, returning enough to drive
// upgradeOneFileToSFSE2 directly.
func newUpgradeFixture(t *testing.T, uploadsDir string, db *sql.DB, claimCode string, plaintext []byte) (finalPath string, row verifyFileRow) {
	t.Helper()
	storedFilename := claimCode + ".dat"
	finalPath = filepath.Join(uploadsDir, storedFilename)

	plainTemp := finalPath + ".plainsrc"
	if err := os.WriteFile(plainTemp, plaintext, 0600); err != nil {
		t.Fatalf("write plain temp: %v", err)
	}
	defer os.Remove(plainTemp)
	if err := utils.EncryptFileStreaming(plainTemp, finalPath, upgradeTestKey); err != nil {
		t.Fatalf("EncryptFileStreaming (SFSE1): %v", err)
	}

	f := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: storedFilename,
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	if err := database.CreateFile(db, f); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	rows, err := listFilesForVerify(db, true)
	if err != nil {
		t.Fatalf("listFilesForVerify: %v", err)
	}
	for _, r := range rows {
		if r.ClaimCode == claimCode {
			return finalPath, r
		}
	}
	t.Fatalf("row for %s not found after insert", claimCode)
	return "", verifyFileRow{}
}

func openUploadsDBFixture(t *testing.T) (uploadsDir string, db *sql.DB) {
	t.Helper()
	tmpDir := t.TempDir()
	uploadsDir = filepath.Join(tmpDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return uploadsDir, db
}

// TestUpgradeOneFileToSFSE2_HappyPath verifies a full, uninterrupted
// SFSE1->SFSE2 upgrade: content round-trips, the DB row gets a fresh
// enc_file_id, an empty sha256_hash gets filled in, and the on-disk file is
// genuinely SFSE2 afterward.
func TestUpgradeOneFileToSFSE2_HappyPath(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := bytes.Repeat([]byte("upgrade-me "), 5000)
	finalPath, row := newUpgradeFixture(t, uploadsDir, db, "happy", plaintext)

	applicable, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashNone)
	if err != nil {
		t.Fatalf("upgradeOneFileToSFSE2: %v", err)
	}
	if !applicable {
		t.Fatal("applicable = false, want true (row is SFSE1)")
	}

	ver, err := utils.PeekSFSEVersion(finalPath)
	if err != nil {
		t.Fatalf("PeekSFSEVersion: %v", err)
	}
	if ver != utils.StreamEncryptionVersionV2 {
		t.Fatalf("version = 0x%02x, want SFSE2", ver)
	}

	rows, err := listFilesForVerify(db, true)
	if err != nil {
		t.Fatalf("listFilesForVerify: %v", err)
	}
	updated := rows[0]
	if len(updated.EncFileID) != utils.SFSE2EncFileIDSize {
		t.Fatalf("enc_file_id length = %d, want %d", len(updated.EncFileID), utils.SFSE2EncFileIDSize)
	}
	if updated.SHA256Hash == "" {
		t.Error("sha256_hash was not filled in")
	}

	// Round-trip through the real production reader.
	f, err := os.Open(finalPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	reader, err := utils.OpenSFSEReader(f, fi, upgradeTestKey, updated.EncFileID, updated.FileSize, updated.SHA256Hash)
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer reader.Close()
	got := make([]byte, len(plaintext))
	if _, err := reader.Read(got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("round-tripped content mismatch")
	}

	// No leftover temp file.
	if _, err := os.Stat(finalPath + ".sfse2upgrade.tmp"); !os.IsNotExist(err) {
		t.Errorf("leftover temp file, stat err = %v", err)
	}
}

// TestUpgradeOneFileToSFSE2_PreservesFileMode is the regression test for the
// database-review MEDIUM finding: a migrated file must keep the original
// file's permission mode, not come out however os.OpenFile's own mode
// argument (0600) happened to leave it. A uid/gid (chown) test is not
// included here — it only exercises anything when running as root, which
// this test suite does not assume.
func TestUpgradeOneFileToSFSE2_PreservesFileMode(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := bytes.Repeat([]byte("mode-preservation "), 2000)
	finalPath, row := newUpgradeFixture(t, uploadsDir, db, "modecheck", plaintext)

	const wantMode = 0640
	if err := os.Chmod(finalPath, wantMode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if _, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashNone); err != nil {
		t.Fatalf("upgradeOneFileToSFSE2: %v", err)
	}

	fi, err := os.Stat(finalPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != os.FileMode(wantMode) {
		t.Errorf("mode after upgrade = %o, want %o (original mode was not preserved)", got, wantMode)
	}
}

// TestUpgradeOneFileToSFSE2_PreservesExistingHash verifies that a row which
// already has a sha256_hash is not overwritten with a recomputed one (and
// that the existing hash still verifies against the unchanged plaintext).
func TestUpgradeOneFileToSFSE2_PreservesExistingHash(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := []byte("hash already known")
	finalPath, row := newUpgradeFixture(t, uploadsDir, db, "hashed", plaintext)

	sum := sha256HexOf(plaintext)
	if _, err := db.Exec(`UPDATE files SET sha256_hash = ? WHERE id = ?`, sum, row.ID); err != nil {
		t.Fatalf("seed sha256_hash: %v", err)
	}
	rows, _ := listFilesForVerify(db, true)
	row = rows[0]
	if row.SHA256Hash != sum {
		t.Fatalf("fixture sha256_hash = %q, want %q", row.SHA256Hash, sum)
	}

	if _, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashNone); err != nil {
		t.Fatalf("upgradeOneFileToSFSE2: %v", err)
	}

	_ = finalPath
	rows, _ = listFilesForVerify(db, true)
	if rows[0].SHA256Hash != sum {
		t.Errorf("sha256_hash changed: got %q, want unchanged %q", rows[0].SHA256Hash, sum)
	}
}

// TestUpgradeOneFileToSFSE2_NotApplicable verifies plaintext and
// already-SFSE2 files are left alone (applicable=false, no error, nothing
// touched).
func TestUpgradeOneFileToSFSE2_NotApplicable(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)

	t.Run("plaintext", func(t *testing.T) {
		content := []byte("plain content")
		storedFilename := "plain.dat"
		path := filepath.Join(uploadsDir, storedFilename)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		f := &models.File{ClaimCode: "plain-nc", OriginalFilename: storedFilename, StoredFilename: storedFilename, FileSize: int64(len(content)), MimeType: "text/plain", ExpiresAt: time.Now().Add(time.Hour)}
		if err := database.CreateFile(db, f); err != nil {
			t.Fatalf("CreateFile: %v", err)
		}
		rows, _ := listFilesForVerify(db, true)
		var row verifyFileRow
		for _, r := range rows {
			if r.ClaimCode == "plain-nc" {
				row = r
			}
		}
		applicable, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashNone)
		if err != nil {
			t.Fatalf("upgradeOneFileToSFSE2: %v", err)
		}
		if applicable {
			t.Error("applicable = true for a plaintext file, want false")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, content) {
			t.Error("plaintext file was modified")
		}
	})

	t.Run("already SFSE2", func(t *testing.T) {
		content := bytes.Repeat([]byte("v2"), 50)
		storedFilename := "already-v2.dat"
		path := filepath.Join(uploadsDir, storedFilename)
		encFileID, err := utils.GenerateEncFileID()
		if err != nil {
			t.Fatalf("GenerateEncFileID: %v", err)
		}
		if err := utils.EncryptFileStreamingV2(writeTemp(t, content), path, upgradeTestKey, encFileID); err != nil {
			t.Fatalf("EncryptFileStreamingV2: %v", err)
		}
		f := &models.File{ClaimCode: "v2-nc", OriginalFilename: storedFilename, StoredFilename: storedFilename, FileSize: int64(len(content)), MimeType: "application/octet-stream", ExpiresAt: time.Now().Add(time.Hour), EncFileID: encFileID}
		if err := database.CreateFile(db, f); err != nil {
			t.Fatalf("CreateFile: %v", err)
		}
		rows, _ := listFilesForVerify(db, true)
		var row verifyFileRow
		for _, r := range rows {
			if r.ClaimCode == "v2-nc" {
				row = r
			}
		}
		before, _ := os.ReadFile(path)
		applicable, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashNone)
		if err != nil {
			t.Fatalf("upgradeOneFileToSFSE2: %v", err)
		}
		if applicable {
			t.Error("applicable = true for an already-SFSE2 file, want false")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Error("already-SFSE2 file was modified")
		}
	})
}

// writeTemp writes content to a fresh temp file and returns its path — a
// small helper for EncryptFileStreamingV2's path-based (not reader-based)
// signature.
func writeTemp(t *testing.T, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "src-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	return f.Name()
}

// --- Crash-safety: commitFormatUpgrade --------------------------------------
//
// Each subtest simulates the process dying at a specific point inside
// commitFormatUpgrade (via the crashPoint parameter) and then asserts the
// invariant documented on that function: the files row and the on-disk file
// must describe either the OLD format+row or the NEW format+row at every
// instant, OR — the one allowed transient state — the row already names the
// new format while the file is still readable in its old one.

// TestUpgradeCrashSafety_BeforeDBCommit simulates a crash right after the
// new-format temp file is written+fsynced, before the DB is touched at all.
// Expected: old file + old DB row, completely untouched; only the orphaned
// temp file exists as debris.
func TestUpgradeCrashSafety_BeforeDBCommit(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := []byte("crash before db commit")
	finalPath, row := newUpgradeFixture(t, uploadsDir, db, "crash1", plaintext)
	origBytes, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read original: %v", err)
	}

	_, err = upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashAfterTempWritten)
	if !errors.Is(err, errSimulatedCrash) {
		t.Fatalf("expected errSimulatedCrash, got %v", err)
	}

	// Original file completely unchanged.
	gotBytes, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read after simulated crash: %v", err)
	}
	if !bytes.Equal(gotBytes, origBytes) {
		t.Error("original file was modified before any commit — crash-safety violated")
	}
	ver, err := utils.PeekSFSEVersion(finalPath)
	if err != nil || ver != utils.StreamEncryptionVersion {
		t.Errorf("original file version = %v/0x%02x, want SFSE1 unchanged", err, ver)
	}

	// DB row unchanged (still no enc_file_id).
	rows, _ := listFilesForVerify(db, true)
	if len(rows[0].EncFileID) != 0 {
		t.Error("DB row was updated before any commit — crash-safety violated")
	}

	// A rerun (as if the operator reran the tool after the crash) must
	// complete cleanly and produce a correct SFSE2 file — resumability.
	rows, _ = listFilesForVerify(db, true)
	if _, err := upgradeOneFileToSFSE2(db, uploadsDir, rows[0], upgradeTestKey, false, crashNone); err != nil {
		t.Fatalf("resume after crash: %v", err)
	}
	if ver, _ := utils.PeekSFSEVersion(finalPath); ver != utils.StreamEncryptionVersionV2 {
		t.Error("resume did not complete the upgrade to SFSE2")
	}
}

// TestUpgradeCrashSafety_AfterDBCommitBeforeRename is the load-bearing case:
// a crash between the DB commit and the rename. The row now names the NEW
// enc_file_id, but the file at finalPath is still the OLD SFSE1 bytes.
// commitFormatUpgrade's doc comment claims this is still safe to read
// through — this test proves it directly, by opening the untouched file
// with the now-updated DB row exactly as a live claim download would.
func TestUpgradeCrashSafety_AfterDBCommitBeforeRename(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := []byte("crash after db commit, before rename - the load bearing case")
	finalPath, row := newUpgradeFixture(t, uploadsDir, db, "crash2", plaintext)

	_, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashAfterDBCommit)
	if !errors.Is(err, errSimulatedCrash) {
		t.Fatalf("expected errSimulatedCrash, got %v", err)
	}

	// File on disk must still be the untouched SFSE1 original.
	ver, err := utils.PeekSFSEVersion(finalPath)
	if err != nil {
		t.Fatalf("PeekSFSEVersion: %v", err)
	}
	if ver != utils.StreamEncryptionVersion {
		t.Fatalf("file version = 0x%02x, want SFSE1 (still not renamed)", ver)
	}

	// DB row must already show the NEW enc_file_id (and a filled-in hash).
	rows, err := listFilesForVerify(db, true)
	if err != nil {
		t.Fatalf("listFilesForVerify: %v", err)
	}
	updatedRow := rows[0]
	if len(updatedRow.EncFileID) != utils.SFSE2EncFileIDSize {
		t.Fatalf("DB row enc_file_id not committed despite crash being after the DB commit step")
	}
	if updatedRow.SHA256Hash == "" {
		t.Fatal("DB row sha256_hash not committed despite crash being after the DB commit step")
	}

	// THE key assertion: a read using the NEW DB row against the STILL-OLD
	// file must succeed and return correct plaintext — proving a request
	// in flight during this exact window is not served corrupt data.
	f, err := os.Open(finalPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	reader, err := utils.OpenSFSEReader(f, fi, upgradeTestKey, updatedRow.EncFileID, updatedRow.FileSize, updatedRow.SHA256Hash)
	if err != nil {
		t.Fatalf("OpenSFSEReader with post-crash DB row against pre-crash file: %v", err)
	}
	defer reader.Close()
	got := make([]byte, len(plaintext))
	if _, err := reader.Read(got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("content mismatch reading the old file through the new DB row")
	}

	// And a rerun must still complete the upgrade (resumable: it keys its
	// "already SFSE2" skip off the on-disk format, so it correctly redoes
	// the encrypt+rename here rather than mistaking the DB row for done).
	if _, err := upgradeOneFileToSFSE2(db, uploadsDir, updatedRow, upgradeTestKey, false, crashNone); err != nil {
		t.Fatalf("resume after crash: %v", err)
	}
	if ver, _ := utils.PeekSFSEVersion(finalPath); ver != utils.StreamEncryptionVersionV2 {
		t.Error("resume did not complete the upgrade to SFSE2")
	}
	rows, _ = listFilesForVerify(db, true)
	f2, err := os.Open(finalPath)
	if err != nil {
		t.Fatalf("open final: %v", err)
	}
	defer f2.Close()
	fi2, _ := f2.Stat()
	reader2, err := utils.OpenSFSEReader(f2, fi2, upgradeTestKey, rows[0].EncFileID, rows[0].FileSize, rows[0].SHA256Hash)
	if err != nil {
		t.Fatalf("OpenSFSEReader after resume: %v", err)
	}
	defer reader2.Close()
	got2 := make([]byte, len(plaintext))
	if _, err := reader2.Read(got2); err != nil {
		t.Fatalf("Read after resume: %v", err)
	}
	if !bytes.Equal(got2, plaintext) {
		t.Error("content mismatch after resume")
	}
}

// TestUpgradeCrashSafety_AfterRename simulates a crash after the rename
// succeeded but before the final post-rename directory fsync. The upgrade
// must be considered fully complete: file is SFSE2, DB row matches, no
// action needed on resume.
func TestUpgradeCrashSafety_AfterRename(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := []byte("crash after rename, before the final fsync")
	finalPath, row := newUpgradeFixture(t, uploadsDir, db, "crash3", plaintext)

	_, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashAfterRename)
	if !errors.Is(err, errSimulatedCrash) {
		t.Fatalf("expected errSimulatedCrash, got %v", err)
	}

	ver, err := utils.PeekSFSEVersion(finalPath)
	if err != nil {
		t.Fatalf("PeekSFSEVersion: %v", err)
	}
	if ver != utils.StreamEncryptionVersionV2 {
		t.Fatalf("file version = 0x%02x, want SFSE2 (rename already succeeded)", ver)
	}

	rows, err := listFilesForVerify(db, true)
	if err != nil {
		t.Fatalf("listFilesForVerify: %v", err)
	}
	updatedRow := rows[0]

	f, err := os.Open(finalPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	reader, err := utils.OpenSFSEReader(f, fi, upgradeTestKey, updatedRow.EncFileID, updatedRow.FileSize, updatedRow.SHA256Hash)
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer reader.Close()
	got := make([]byte, len(plaintext))
	if _, err := reader.Read(got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Error("content mismatch")
	}

	// A rerun must find the file already SFSE2 and do nothing further.
	applicable, err := upgradeOneFileToSFSE2(db, uploadsDir, updatedRow, upgradeTestKey, false, crashNone)
	if err != nil {
		t.Fatalf("resume after crash: %v", err)
	}
	if applicable {
		t.Error("resume treated an already-fully-upgraded file as applicable again")
	}
}

// TestUpgradeOneFileToSFSE2_StaleTempDoesNotBlockRerun is the regression
// test for the LOW finding that a fixed-name temp file left behind by a
// prior crashed run (before O_EXCL's create) would permanently block every
// later run with EEXIST. Pre-creates a bogus leftover temp file at the
// exact path upgradeOneFileToSFSE2 uses, then asserts a normal run still
// succeeds (the stale temp is removed first).
func TestUpgradeOneFileToSFSE2_StaleTempDoesNotBlockRerun(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := []byte("stale temp from a simulated prior crash")
	finalPath, row := newUpgradeFixture(t, uploadsDir, db, "staletemp", plaintext)

	stalePath := finalPath + ".sfse2upgrade.tmp"
	if err := os.WriteFile(stalePath, []byte("leftover garbage from a crashed run"), 0600); err != nil {
		t.Fatalf("seed stale temp file: %v", err)
	}

	applicable, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashNone)
	if err != nil {
		t.Fatalf("upgradeOneFileToSFSE2 blocked by stale temp file: %v", err)
	}
	if !applicable {
		t.Fatal("applicable = false, want true")
	}
	if ver, _ := utils.PeekSFSEVersion(finalPath); ver != utils.StreamEncryptionVersionV2 {
		t.Error("upgrade did not complete despite the stale temp file being cleared")
	}
}

// TestCommitFormatUpgrade_FinalPathVanishedSkipsRename is the regression
// test for the database-review finding that background expiry cleanup
// (which deletes a row and its file together once expires_at has passed)
// can race commitFormatUpgrade: if it lands in the window between this
// function's own DB commit and its rename, finalPath is gone by the time
// the rename would run, and renaming the temp file in anyway would create
// a genuine orphan (a file with no matching DB row at all).
//
// This test exercises the stat-check in isolation by deleting finalPath
// (simulating "the file is gone by the time we get to the rename check",
// regardless of exactly when in the function's execution that happened —
// indistinguishable from the function's own point of view) while leaving
// the DB row itself intact, so commitFormatUpgrade's own DB commit step
// still succeeds normally and the stat-check is what's actually under
// test. (A concurrent deletion landing even earlier — before this
// function's own UPDATE reaches the row at all — is a distinct,
// pre-existing race already caught by updateEncFileIDAndHash's
// RowsAffected==0 check; not what this test is about.)
func TestCommitFormatUpgrade_FinalPathVanishedSkipsRename(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := []byte("file deleted concurrently before the rename step")
	finalPath, row := newUpgradeFixture(t, uploadsDir, db, "vanish1", plaintext)

	newEncFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	tempPath := finalPath + ".sfse2upgrade.tmp"
	tempFile, err := os.Create(tempPath)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if err := utils.EncryptFileStreamingV2FromReader(tempFile, bytes.NewReader(plaintext), upgradeTestKey, newEncFileID, int64(len(plaintext))); err != nil {
		t.Fatalf("encrypt to temp: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}

	// Simulate the concurrent expiry-cleanup sweep deleting the file (the
	// row is left alone here — see the doc comment above for why).
	if err := os.Remove(finalPath); err != nil {
		t.Fatalf("simulate concurrent file deletion: %v", err)
	}

	err = commitFormatUpgrade(db, uploadsDir, finalPath, tempPath, row.ID, row.StoredFilename, newEncFileID, "", false, crashNone)
	if !errors.Is(err, errFinalPathVanishedDuringCommit) {
		t.Fatalf("commitFormatUpgrade error = %v, want errFinalPathVanishedDuringCommit", err)
	}

	// No rename happened: the temp file is still sitting at tempPath
	// (callers are responsible for removing it — see the doc comment), and
	// nothing was created at finalPath.
	if _, statErr := os.Stat(tempPath); statErr != nil {
		t.Errorf("temp file should still exist at %s: %v", tempPath, statErr)
	}
	if _, statErr := os.Stat(finalPath); !os.IsNotExist(statErr) {
		t.Errorf("finalPath should still not exist, stat err = %v", statErr)
	}

	// The DB row's own update DID land (it happens before the stat-check),
	// even though the rename that would have matched it never happened —
	// exactly the transient, safe-to-read-through intermediate state
	// commitFormatUpgrade's main doc comment describes for the ordinary
	// crash-between-commit-and-rename case. There's no file at finalPath
	// at all here (not even the old one), which is a harsher version of
	// that state — a claim download would get a clean "not found", not
	// corrupt output.
	rows, err := listFilesForVerify(db, true)
	if err != nil {
		t.Fatalf("listFilesForVerify: %v", err)
	}
	if len(rows[0].EncFileID) != utils.SFSE2EncFileIDSize {
		t.Errorf("DB row enc_file_id not committed (expected the pre-rename DB commit to have landed regardless)")
	}
}

// TestAcquireProcessLock_RefusesConcurrent verifies the flock-based process
// lock actually prevents a second concurrent acquisition against the same
// uploads directory.
// TestUpgradeOneFileToSFSE2_RejectsInvalidStoredFilename is the regression
// test for the LOW finding that row.StoredFilename was never validated
// before being joined into a filesystem path. A path-traversal or
// separator-containing stored_filename must be rejected before any disk
// access, not passed straight into filepath.Join+os.Open.
func TestUpgradeOneFileToSFSE2_RejectsInvalidStoredFilename(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	row := verifyFileRow{ID: 1, StoredFilename: "../../../etc/passwd", FileSize: 10}

	_, err := upgradeOneFileToSFSE2(db, uploadsDir, row, upgradeTestKey, false, crashNone)
	if err == nil {
		t.Fatal("upgradeOneFileToSFSE2 succeeded with a path-traversal stored_filename, want error")
	}
}

func TestAcquireProcessLock_RefusesConcurrent(t *testing.T) {
	uploadsDir, _ := openUploadsDBFixture(t)

	unlock, err := acquireProcessLock(uploadsDir)
	if err != nil {
		t.Fatalf("first acquireProcessLock: %v", err)
	}
	defer unlock()

	if _, err := acquireProcessLock(uploadsDir); err == nil {
		t.Fatal("second concurrent acquireProcessLock succeeded, want error")
	}
}

// TestRunUpgradeFormat_DryRunChangesNothing verifies --upgrade-format
// --dry-run reports candidates but writes nothing to disk or the DB.
func TestRunUpgradeFormat_DryRunChangesNothing(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	plaintext := []byte("dry run must not touch this")
	finalPath, _ := newUpgradeFixture(t, uploadsDir, db, "dryrun1", plaintext)
	before, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	report, err := runUpgradeFormat(db, uploadsDir, upgradeTestKey, true /* dryRun */)
	if err != nil {
		t.Fatalf("runUpgradeFormat: %v", err)
	}
	if report.DryRunCandidates != 1 {
		t.Errorf("DryRunCandidates = %d, want 1", report.DryRunCandidates)
	}
	if report.Upgraded != 0 {
		t.Errorf("Upgraded = %d, want 0 (dry run)", report.Upgraded)
	}

	after, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("dry run modified the file")
	}
	rows, _ := listFilesForVerify(db, true)
	if len(rows[0].EncFileID) != 0 {
		t.Error("dry run modified the DB row")
	}
}

// TestRunUpgradeFormat_RequiresEncKey verifies --upgrade-format refuses to
// run without a valid encryption key.
func TestRunUpgradeFormat_RequiresEncKey(t *testing.T) {
	uploadsDir, db := openUploadsDBFixture(t)
	if _, err := runUpgradeFormat(db, uploadsDir, "", false); err == nil {
		t.Fatal("runUpgradeFormat with empty key succeeded, want error")
	}
	if _, err := runUpgradeFormat(db, uploadsDir, "tooshort", false); err == nil {
		t.Fatal("runUpgradeFormat with invalid key succeeded, want error")
	}
}
