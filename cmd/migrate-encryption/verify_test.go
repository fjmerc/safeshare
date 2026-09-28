package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

const verifyTestKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
const verifyTestWrongKey = "9999999999999999999999999999999999999999999999999999999999999999"

// setupVerifyFixture builds a small SQLite DB + uploads directory with a mix
// of good and bad rows, covering every --verify code path:
//
//  1. plain.dat        - plaintext, good
//  2. legacy.dat        - legacy single-shot ciphertext, good
//  3. good.sfse2         - SFSE2, correct key+hash, good
//  4. wrongkey.sfse2      - SFSE2, structurally fine, but --verify-decrypt
//     with the wrong key must catch it
//  5. does-not-exist.dat  - DB row with no file on disk (missing)
//  6. corrupt.dat        - on-disk bytes matching no recognized format/size
func setupVerifyFixture(t *testing.T) (dbPath, uploadsDir string) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath = filepath.Join(tmpDir, "test.db")
	uploadsDir = filepath.Join(tmpDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	create := func(claimCode, storedFilename string, size int64, sha256hex string) int64 {
		t.Helper()
		f := &models.File{
			ClaimCode:        claimCode,
			OriginalFilename: storedFilename,
			StoredFilename:   storedFilename,
			FileSize:         size,
			MimeType:         "application/octet-stream",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			SHA256Hash:       sha256hex,
		}
		if err := database.CreateFile(db, f); err != nil {
			t.Fatalf("CreateFile(%s): %v", claimCode, err)
		}
		return f.ID
	}

	// 1. Plaintext file — good.
	plainData := []byte("this is a perfectly ordinary plaintext file")
	writeUploadFile(t, uploadsDir, "plain.dat", plainData)
	create("plaincode0001", "plain.dat", int64(len(plainData)), "")

	// 2. Legacy single-shot encrypted file — good.
	legacyPlain := []byte("legacy ciphertext contents")
	legacyCipher, err := utils.EncryptFile(legacyPlain, verifyTestKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	writeUploadFile(t, uploadsDir, "legacy.dat", legacyCipher)
	create("legacycode001", "legacy.dat", int64(len(legacyPlain)), "")

	// 3. SFSE2 file — good, correct key and hash.
	sfse2Plain := bytes.Repeat([]byte("safeshare-verify-fixture "), 500)
	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	sfse2Path := filepath.Join(uploadsDir, "good.sfse2")
	if err := utils.EncryptFileStreamingV2(writeTempPlainFile(t, sfse2Plain), sfse2Path, verifyTestKey, encFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}
	id := create("sfse2good0001", "good.sfse2", int64(len(sfse2Plain)), sha256HexOf(sfse2Plain))
	setEncFileID(t, db, id, encFileID)

	// 4. SFSE2 file, structurally fine — only fails under --verify-decrypt
	// with the wrong key.
	wrongKeyPlain := bytes.Repeat([]byte("needs the right key "), 300)
	wrongKeyEncFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	wrongKeyPath := filepath.Join(uploadsDir, "wrongkey.sfse2")
	if err := utils.EncryptFileStreamingV2(writeTempPlainFile(t, wrongKeyPlain), wrongKeyPath, verifyTestKey, wrongKeyEncFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}
	id = create("wrongkey00001", "wrongkey.sfse2", int64(len(wrongKeyPlain)), sha256HexOf(wrongKeyPlain))
	setEncFileID(t, db, id, wrongKeyEncFileID)

	// 5. Missing file — DB row with no corresponding file on disk.
	create("missingfile01", "does-not-exist.dat", 12345, "")

	// 6. Size-mismatch file — on-disk bytes match nothing recognized.
	writeUploadFile(t, uploadsDir, "corrupt.dat", []byte("short"))
	create("corruptfile01", "corrupt.dat", 999999, "")

	return dbPath, uploadsDir
}

func writeUploadFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatalf("WriteFile(%s): %v", name, err)
	}
}

func writeTempPlainFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plain.src")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// setEncFileID sets files.enc_file_id directly — CreateFile doesn't take it
// (enc_file_id is an SFSE2-only, post-encryption-time value), and this is a
// test fixture, not a path any production code should share.
func setEncFileID(t *testing.T, db *sql.DB, id int64, encFileID []byte) {
	t.Helper()
	if _, err := db.Exec(`UPDATE files SET enc_file_id = ? WHERE id = ?`, encFileID, id); err != nil {
		t.Fatalf("setEncFileID: %v", err)
	}
}

func sha256HexOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestRunVerify_GoodAndBadRows(t *testing.T) {
	dbPath, uploadsDir := setupVerifyFixture(t)

	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	report, err := runVerify(db, uploadsDir, verifyTestKey, false, false, false)
	if err != nil {
		t.Fatalf("runVerify: %v", err)
	}

	if report.TotalRows != 6 {
		t.Fatalf("TotalRows = %d, want 6", report.TotalRows)
	}
	if report.Counts["plaintext"] != 1 {
		t.Fatalf("plaintext count = %d, want 1", report.Counts["plaintext"])
	}
	if report.Counts["legacy"] != 1 {
		t.Fatalf("legacy count = %d, want 1", report.Counts["legacy"])
	}
	// Both SFSE2 rows classify fine without --verify-decrypt (the "wrong
	// key" one only fails once we actually try to decrypt).
	if report.Counts["sfse2"] != 2 {
		t.Fatalf("sfse2 count = %d, want 2", report.Counts["sfse2"])
	}
	if report.Counts[verifyBucketMissingFile] != 1 {
		t.Fatalf("missing count = %d, want 1", report.Counts[verifyBucketMissingFile])
	}
	if len(report.Problems) != 2 { // missing file + corrupt/size-mismatch file
		t.Fatalf("Problems = %d, want 2: %+v", len(report.Problems), report.Problems)
	}

	for _, p := range report.Problems {
		if strings.Contains(p.ClaimCodePrefix, "missingfile01") || strings.Contains(p.ClaimCodePrefix, "corruptfile01") {
			t.Fatalf("claim code was not redacted: %q", p.ClaimCodePrefix)
		}
	}

	var buf bytes.Buffer
	printVerifyReport(&buf, report)
	out := buf.String()
	if !strings.Contains(out, "Total files checked: 6") {
		t.Fatalf("report missing total line:\n%s", out)
	}
	if !strings.Contains(out, "does-not-exist.dat") {
		t.Fatalf("report missing problem detail for missing file:\n%s", out)
	}
}

func TestRunVerify_VerifyDecryptCatchesWrongKey(t *testing.T) {
	dbPath, uploadsDir := setupVerifyFixture(t)

	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	report, err := runVerify(db, uploadsDir, verifyTestWrongKey, false, true, false)
	if err != nil {
		t.Fatalf("runVerify: %v", err)
	}

	found := false
	for _, p := range report.Problems {
		if strings.Contains(p.StoredFilename, "sfse2") && strings.Contains(p.Issue, "wrong key") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a 'wrong key' problem among: %+v", report.Problems)
	}
}

func TestRunVerify_NoKeyReportsKeyMissing(t *testing.T) {
	dbPath, uploadsDir := setupVerifyFixture(t)

	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	report, err := runVerify(db, uploadsDir, "", false, false, false)
	if err != nil {
		t.Fatalf("runVerify: %v", err)
	}

	keyMissing := 0
	for _, p := range report.Problems {
		if strings.Contains(p.Issue, "key missing") {
			keyMissing++
		}
	}
	// legacy.dat + both sfse2 files all require a key.
	if keyMissing != 3 {
		t.Fatalf("key-missing problems = %d, want 3: %+v", keyMissing, report.Problems)
	}
	if report.Counts["plaintext"] != 1 {
		t.Fatalf("plaintext should still classify without a key; count = %d", report.Counts["plaintext"])
	}
}

func TestRedactClaimCode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"abcd", "abcd"},
		{"abcdefgh", "abcd..."},
	}
	for _, tt := range tests {
		if got := redactClaimCode(tt.in); got != tt.want {
			t.Errorf("redactClaimCode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// setupVerifyHashFixture builds a DB + uploads directory with one good and
// one hash-mismatched row per format that --verify-hash actually hashes
// (plaintext, SFSE1, SFSE2), to exercise the "hash mismatch" problem path
// end to end for each.
func setupVerifyHashFixture(t *testing.T) (dbPath, uploadsDir string) {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath = filepath.Join(tmpDir, "test.db")
	uploadsDir = filepath.Join(tmpDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	create := func(claimCode, storedFilename string, size int64, sha256hex string) int64 {
		t.Helper()
		f := &models.File{
			ClaimCode:        claimCode,
			OriginalFilename: storedFilename,
			StoredFilename:   storedFilename,
			FileSize:         size,
			MimeType:         "application/octet-stream",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			SHA256Hash:       sha256hex,
		}
		if err := database.CreateFile(db, f); err != nil {
			t.Fatalf("CreateFile(%s): %v", claimCode, err)
		}
		return f.ID
	}
	wrongHash := sha256HexOf([]byte("this is not the content of any fixture file"))

	// Plaintext, good hash.
	plainGood := []byte("plaintext content that matches its stored hash")
	writeUploadFile(t, uploadsDir, "plain-good.dat", plainGood)
	create("plaingoodhash", "plain-good.dat", int64(len(plainGood)), sha256HexOf(plainGood))

	// Plaintext, wrong hash.
	plainBad := []byte("plaintext content that does NOT match its stored hash")
	writeUploadFile(t, uploadsDir, "plain-bad.dat", plainBad)
	create("plainbadhash1", "plain-bad.dat", int64(len(plainBad)), wrongHash)

	// SFSE1, wrong hash.
	sfse1Plain := bytes.Repeat([]byte("sfse1 content for hash mismatch test "), 50)
	sfse1Path := filepath.Join(uploadsDir, "sfse1-bad.dat")
	if err := utils.EncryptFileStreaming(writeTempPlainFile(t, sfse1Plain), sfse1Path, verifyTestKey); err != nil {
		t.Fatalf("EncryptFileStreaming: %v", err)
	}
	create("sfse1badhash1", "sfse1-bad.dat", int64(len(sfse1Plain)), wrongHash)

	// SFSE2, wrong hash.
	sfse2Plain := bytes.Repeat([]byte("sfse2 content for hash mismatch test "), 50)
	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	sfse2Path := filepath.Join(uploadsDir, "sfse2-bad.dat")
	if err := utils.EncryptFileStreamingV2(writeTempPlainFile(t, sfse2Plain), sfse2Path, verifyTestKey, encFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}
	id := create("sfse2badhash1", "sfse2-bad.dat", int64(len(sfse2Plain)), wrongHash)
	setEncFileID(t, db, id, encFileID)

	// SFSE2, no stored hash at all — informational, not a problem.
	sfse2NoHashPlain := bytes.Repeat([]byte("sfse2 content with no stored hash "), 50)
	noHashEncFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	sfse2NoHashPath := filepath.Join(uploadsDir, "sfse2-nohash.dat")
	if err := utils.EncryptFileStreamingV2(writeTempPlainFile(t, sfse2NoHashPlain), sfse2NoHashPath, verifyTestKey, noHashEncFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}
	id = create("sfse2nohash01", "sfse2-nohash.dat", int64(len(sfse2NoHashPlain)), "")
	setEncFileID(t, db, id, noHashEncFileID)

	return dbPath, uploadsDir
}

func TestRunVerify_VerifyHashCatchesMismatchesAcrossFormats(t *testing.T) {
	dbPath, uploadsDir := setupVerifyHashFixture(t)

	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	report, err := runVerify(db, uploadsDir, verifyTestKey, false, false, true)
	if err != nil {
		t.Fatalf("runVerify: %v", err)
	}

	if report.TotalRows != 5 {
		t.Fatalf("TotalRows = %d, want 5", report.TotalRows)
	}

	wantMismatch := map[string]bool{
		"plain-bad.dat": false,
		"sfse1-bad.dat": false,
		"sfse2-bad.dat": false,
	}
	for _, p := range report.Problems {
		if _, ok := wantMismatch[p.StoredFilename]; ok {
			if !strings.Contains(p.Issue, "hash mismatch") {
				t.Errorf("problem for %s = %q, want it to mention 'hash mismatch'", p.StoredFilename, p.Issue)
			}
			wantMismatch[p.StoredFilename] = true
		}
	}
	for name, found := range wantMismatch {
		if !found {
			t.Errorf("expected a hash-mismatch problem for %s, got problems: %+v", name, report.Problems)
		}
	}

	// This is the "exit 1" condition main() checks: any problems at all.
	if len(report.Problems) == 0 {
		t.Fatalf("expected len(report.Problems) > 0 (would exit 0, want exit 1)")
	}

	// The good plaintext row and the no-stored-hash SFSE2 row must NOT be
	// reported as problems.
	for _, p := range report.Problems {
		if p.StoredFilename == "plain-good.dat" || p.StoredFilename == "sfse2-nohash.dat" {
			t.Errorf("unexpected problem for a file that should have passed: %+v", p)
		}
	}
	if report.Counts[verifyBucketNoStoredHash] != 1 {
		t.Fatalf("no_stored_hash count = %d, want 1 (sfse2-nohash.dat)", report.Counts[verifyBucketNoStoredHash])
	}
}

// TestOpenReadOnlyDB_RefusesWrites guards the --verify promise that it can
// never modify the database it inspects.
func TestOpenReadOnlyDB_RefusesWrites(t *testing.T) {
	// A space and '#' in the path check that the file: URI is escaped.
	dir := filepath.Join(t.TempDir(), "my data #1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ro.db")
	rw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rw.Exec("CREATE TABLE t (a INTEGER)"); err != nil {
		t.Fatal(err)
	}
	rw.Close()

	db, err := openReadOnlyDB(path)
	if err != nil {
		t.Fatalf("openReadOnlyDB: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("INSERT INTO t VALUES (1)"); err == nil {
		t.Fatal("write succeeded on a database opened by openReadOnlyDB")
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM t").Scan(&n); err != nil {
		t.Fatalf("read failed: %v", err)
	}
}
