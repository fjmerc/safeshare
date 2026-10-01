package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/fjmerc/safeshare/internal/utils"
)

// verifyHashLegacyMaxBytes caps how large a legacy (pre-SFSE, single-shot
// AES-256-GCM) file --verify-hash will buffer fully in memory to run it
// through the existing (non-streaming) utils.DecryptFile. Legacy files
// predate streaming encryption entirely, so there is no streaming decrypt
// path to reuse for them; rather than risk OOMing a --verify run on an
// unusually large legacy file, anything over this cap is skipped with a
// note instead of decrypted.
const verifyHashLegacyMaxBytes = 256 * 1024 * 1024

// verifyBucketNoStoredHash counts files where --verify-hash could not
// compare against files.sha256_hash because the row has none (common for
// files uploaded before SHA-256 tracking existed). This is informational,
// not a problem: for SFSE1/SFSE2 and legacy files, the AEAD tag / GCM tag
// check that --verify-hash still performs already catches corruption and
// tampering even without a stored hash to compare against.
const verifyBucketNoStoredHash = "no_stored_hash"

// verifyBucketSkippedLargeLegacy counts legacy files --verify-hash declined
// to decrypt because they exceed verifyHashLegacyMaxBytes. Informational,
// not a problem — see verifyHashLegacyMaxBytes's doc comment.
const verifyBucketSkippedLargeLegacy = "skipped_large_legacy"

// verifyFileRow is the subset of a files row --verify needs. It is fetched
// with a hand-rolled query (rather than database.GetAllFiles) because it
// needs enc_file_id, which that shared helper doesn't select, and because
// this tool must never risk sharing a write-capable query path with the
// rest of the codebase.
type verifyFileRow struct {
	ID               int64
	ClaimCode        string
	OriginalFilename string
	StoredFilename   string
	FileSize         int64
	SHA256Hash       string
	EncFileID        []byte
}

// listFilesForVerify reads file rows directly from db (opened read-only by
// the caller). includeExpired controls whether expired rows are included.
//
// Also reused by the mutating commands in this package (migrateEncryption's
// legacy branch and runUpgradeFormat — see upgrade.go) as their file
// listing: both need enc_file_id, same as --verify, and per this function's
// original rationale, this tool deliberately keeps one hand-rolled query for
// anything needing enc_file_id rather than widening the shared
// database.GetAllFiles helper other tools/paths also depend on.
func listFilesForVerify(db *sql.DB, includeExpired bool) ([]verifyFileRow, error) {
	query := `
		SELECT id, claim_code, original_filename, stored_filename, file_size, sha256_hash, enc_file_id
		FROM files
	`
	if !includeExpired {
		query += " WHERE datetime(expires_at) > datetime('now')"
	}
	query += " ORDER BY id"

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query files: %w", err)
	}
	defer rows.Close()

	var out []verifyFileRow
	for rows.Next() {
		var row verifyFileRow
		var sha256Hash sql.NullString
		if err := rows.Scan(&row.ID, &row.ClaimCode, &row.OriginalFilename, &row.StoredFilename, &row.FileSize, &sha256Hash, &row.EncFileID); err != nil {
			return nil, fmt.Errorf("failed to scan file row: %w", err)
		}
		if sha256Hash.Valid {
			row.SHA256Hash = sha256Hash.String
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate file rows: %w", err)
	}
	return out, nil
}

// verifyProblem describes one file that failed classification or structural
// validation. ClaimCodePrefix is deliberately truncated — this report may
// be pasted into a support ticket or CI log.
type verifyProblem struct {
	ClaimCodePrefix string
	StoredFilename  string
	DBSize          int64
	DiskSize        int64 // -1 if the file could not be stat'd
	Issue           string
}

// verifyReport summarizes a --verify run: counts of files by recognized
// format (plus special buckets for missing files and problems), and the
// full list of problems.
type verifyReport struct {
	TotalRows int
	Counts    map[string]int
	Problems  []verifyProblem
}

const (
	verifyBucketMissingFile = "missing_file"

	// verifyBucketUpgradableToSFSE2 counts files classified as SFSE1 — every
	// one of them is a candidate for `--upgrade-format` (master finding #10:
	// SFSE1 has no per-chunk AAD, so it can't detect truncation, reordering,
	// or cross-file splicing the way SFSE2 can). Counted unconditionally
	// (not gated on --verify-hash/--verify-decrypt) since it only needs the
	// format classification, not a content read.
	verifyBucketUpgradableToSFSE2 = "upgradable_to_sfse2"
)

// runVerify never writes to db or to any file under uploadsDir — it only
// opens stored files for reading (os.Open) and, when verifyDecrypt is set,
// calls SFSEReader.Prime to decrypt the first chunk of SFSE files as a key
// check; with verifyHash set, it additionally reads every byte of every
// file (see verifyOneFile). encryptionKey may be empty, in which case any
// file requiring a key is reported as a "key missing" problem instead of
// being opened.
func runVerify(db *sql.DB, uploadsDir, encryptionKey string, includeExpired, verifyDecrypt, verifyHash bool) (*verifyReport, error) {
	rows, err := listFilesForVerify(db, includeExpired)
	if err != nil {
		return nil, err
	}

	keyEnabled := utils.IsEncryptionEnabled(encryptionKey)

	report := &verifyReport{
		TotalRows: len(rows),
		Counts:    map[string]int{},
	}

	for _, row := range rows {
		if err := utils.ValidateStoredFilename(row.StoredFilename); err != nil {
			report.Counts["problem"]++
			report.Problems = append(report.Problems, verifyProblem{
				ClaimCodePrefix: redactClaimCode(row.ClaimCode),
				StoredFilename:  row.StoredFilename,
				DBSize:          row.FileSize,
				DiskSize:        -1,
				Issue:           "invalid stored_filename, refusing to touch disk: " + err.Error(),
			})
			continue
		}
		path := filepath.Join(uploadsDir, row.StoredFilename)

		f, err := os.Open(path)
		if err != nil {
			report.Counts[verifyBucketMissingFile]++
			report.Problems = append(report.Problems, verifyProblem{
				ClaimCodePrefix: redactClaimCode(row.ClaimCode),
				StoredFilename:  row.StoredFilename,
				DBSize:          row.FileSize,
				DiskSize:        -1,
				Issue:           "file missing or unreadable: " + err.Error(),
			})
			continue
		}

		format, infoBucket, problem := verifyOneFile(f, row, keyEnabled, encryptionKey, verifyDecrypt, verifyHash)
		f.Close()

		if problem != nil {
			report.Counts["problem"]++
			report.Problems = append(report.Problems, *problem)
			continue
		}
		report.Counts[format.String()]++
		if format == utils.FormatSFSE1 {
			report.Counts[verifyBucketUpgradableToSFSE2]++
		}
		if infoBucket != "" {
			report.Counts[infoBucket]++
		}
	}

	sort.Slice(report.Problems, func(i, j int) bool {
		return report.Problems[i].StoredFilename < report.Problems[j].StoredFilename
	})

	return report, nil
}

// verifyOneFile classifies and structurally validates a single already-open
// file, optionally (verifyDecrypt) priming the first SFSE chunk to check the
// key, and optionally (verifyHash) reading every byte to check content
// integrity end to end. Returns the classified format, an informational
// bucket name (verifyBucketNoStoredHash / verifyBucketSkippedLargeLegacy,
// or "" for nothing to note), and a nil problem on success — or
// FormatUnknown and a populated *verifyProblem on failure.
func verifyOneFile(f *os.File, row verifyFileRow, keyEnabled bool, encryptionKey string, verifyDecrypt, verifyHash bool) (format utils.StoredFormat, infoBucket string, problem *verifyProblem) {
	fi, err := f.Stat()
	if err != nil {
		return utils.FormatUnknown, "", &verifyProblem{
			ClaimCodePrefix: redactClaimCode(row.ClaimCode),
			StoredFilename:  row.StoredFilename,
			DBSize:          row.FileSize,
			DiskSize:        -1,
			Issue:           "stat failed: " + err.Error(),
		}
	}

	format, err = utils.ClassifyStoredFile(f, fi, row.FileSize, keyEnabled)
	if err != nil {
		issue := "bad header or size mismatch: " + err.Error()
		if err == utils.ErrEncryptionKeyMissing {
			issue = "key missing: file is encrypted but no --enckey was supplied"
		}
		return utils.FormatUnknown, "", &verifyProblem{
			ClaimCodePrefix: redactClaimCode(row.ClaimCode),
			StoredFilename:  row.StoredFilename,
			DBSize:          row.FileSize,
			DiskSize:        fi.Size(),
			Issue:           issue,
		}
	}

	claimPrefix := redactClaimCode(row.ClaimCode)

	switch format {
	case utils.FormatSFSE1, utils.FormatSFSE2:
		// Structural validation via OpenSFSEReader — redundant with
		// ClassifyStoredFile's own size check in the common case, but it
		// also exercises the SFSE2 header total_plaintext_len cross-check,
		// the enc_file_id length check (which ClassifyStoredFile doesn't
		// have enough inputs to perform), and gives --verify-decrypt/
		// --verify-hash something to Prime()/Read().
		reader, err := utils.OpenSFSEReader(f, fi, encryptionKey, row.EncFileID, row.FileSize, row.SHA256Hash)
		if err != nil {
			return utils.FormatUnknown, "", &verifyProblem{
				ClaimCodePrefix: claimPrefix,
				StoredFilename:  row.StoredFilename,
				DBSize:          row.FileSize,
				DiskSize:        fi.Size(),
				Issue:           "bad header: " + err.Error(),
			}
		}
		defer reader.Close()

		if verifyDecrypt && !verifyHash {
			if err := reader.Prime(0); err != nil {
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           "wrong key (first chunk failed to decrypt): " + err.Error(),
				}
			}
		}

		if verifyHash {
			// A full sequential read from offset 0 (the reader's position
			// after Open, untouched by the Stat/Classify calls above)
			// authenticates every chunk's AEAD tag in order and, when the
			// row has a stored hash, verifies the whole-file SHA-256 on
			// the final chunk (see SFSEReader's doc comment).
			if _, copyErr := io.Copy(io.Discard, reader); copyErr != nil && copyErr != io.EOF {
				// Security-audit finding (round 4): these must be checked
				// most-specific-sentinel-first. ErrSFSEHashMismatch,
				// ErrSFSEChunkAuthFailed, and the (rarer) other
				// ErrSFSE2IntegrityCheckFailed-wrapping cases (currently
				// just ErrSFSEShortRead) all wrap the same umbrella
				// sentinel, so checking the umbrella first would always
				// match and mislabel every case as the first branch's
				// text — see utils.ErrSFSE2IntegrityCheckFailed's doc
				// comment. A plain I/O error (not wrapped in the umbrella
				// at all) falls through to the "read error" default.
				issue := "read error: " + copyErr.Error()
				switch {
				case errors.Is(copyErr, utils.ErrSFSEHashMismatch):
					issue = "hash mismatch: " + copyErr.Error()
				case errors.Is(copyErr, utils.ErrSFSEChunkAuthFailed):
					issue = "chunk authentication failed: " + copyErr.Error()
				case errors.Is(copyErr, utils.ErrSFSE2IntegrityCheckFailed):
					issue = "short read / other integrity failure: " + copyErr.Error()
				}
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           issue,
				}
			}
			if row.SHA256Hash == "" {
				infoBucket = verifyBucketNoStoredHash
			}
		}

	case utils.FormatPlaintext:
		if verifyHash {
			if row.SHA256Hash == "" {
				infoBucket = verifyBucketNoStoredHash
				break
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           "seek failed: " + err.Error(),
				}
			}
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           "read failed: " + err.Error(),
				}
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != row.SHA256Hash {
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           fmt.Sprintf("hash mismatch: computed %s, db has %s", got, row.SHA256Hash),
				}
			}
		}

	case utils.FormatLegacy:
		if verifyHash {
			if !keyEnabled {
				// ClassifyStoredFile would already have reported this as
				// ErrEncryptionKeyMissing before we ever get here — this
				// branch is unreachable in practice, kept only so a future
				// reordering can't silently skip the key check.
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           "key missing: file is encrypted but no --enckey was supplied",
				}
			}
			if fi.Size() > verifyHashLegacyMaxBytes {
				// utils.DecryptFile is the only legacy decrypt path this
				// codebase has, and it's whole-buffer (no streaming legacy
				// decryptor exists — legacy predates SFSE entirely). Rather
				// than risk OOMing a --verify run, large legacy files are
				// skipped with a note instead of decrypted.
				infoBucket = verifyBucketSkippedLargeLegacy
				break
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           "seek failed: " + err.Error(),
				}
			}
			ciphertext, err := io.ReadAll(f)
			if err != nil {
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           "read failed: " + err.Error(),
				}
			}
			plaintext, err := utils.DecryptFile(ciphertext, encryptionKey)
			if err != nil {
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           "chunk authentication failed: legacy GCM tag check failed: " + err.Error(),
				}
			}
			if row.SHA256Hash == "" {
				infoBucket = verifyBucketNoStoredHash
				break
			}
			sum := sha256.Sum256(plaintext)
			if got := hex.EncodeToString(sum[:]); got != row.SHA256Hash {
				return utils.FormatUnknown, "", &verifyProblem{
					ClaimCodePrefix: claimPrefix,
					StoredFilename:  row.StoredFilename,
					DBSize:          row.FileSize,
					DiskSize:        fi.Size(),
					Issue:           fmt.Sprintf("hash mismatch: computed %s, db has %s", got, row.SHA256Hash),
				}
			}
		}
	}

	return format, infoBucket, nil
}

// redactClaimCode keeps only a short, non-guessable prefix of a claim code
// so a --verify report is safe to paste into a ticket or log aggregator.
func redactClaimCode(code string) string {
	const keep = 4
	if len(code) <= keep {
		return code
	}
	return code[:keep] + "..."
}

// printVerifyReport writes a human-readable summary of report to w.
func printVerifyReport(w io.Writer, report *verifyReport) {
	fmt.Fprintln(w, "\n=== Verify Summary ===")
	fmt.Fprintf(w, "Total files checked: %d\n", report.TotalRows)

	formats := []string{
		utils.FormatPlaintext.String(),
		utils.FormatSFSE1.String(),
		utils.FormatSFSE2.String(),
		utils.FormatLegacy.String(),
	}
	for _, name := range formats {
		fmt.Fprintf(w, "  %-12s %d\n", name+":", report.Counts[name])
	}
	fmt.Fprintf(w, "  %-12s %d\n", "missing:", report.Counts[verifyBucketMissingFile])
	fmt.Fprintf(w, "  %-12s %d\n", "problems:", len(report.Problems))

	if n := report.Counts[verifyBucketNoStoredHash]; n > 0 {
		fmt.Fprintf(w, "  %-12s %d (--verify-hash: no files.sha256_hash to compare against; AEAD/GCM tag was still checked)\n", "no_hash:", n)
	}
	if n := report.Counts[verifyBucketSkippedLargeLegacy]; n > 0 {
		fmt.Fprintf(w, "  %-12s %d (legacy file over the --verify-hash whole-buffer size cap; not decrypted)\n", "skipped:", n)
	}
	if n := report.Counts[verifyBucketUpgradableToSFSE2]; n > 0 {
		fmt.Fprintf(w, "  %-12s %d (SFSE1 — no per-chunk AAD; run with --upgrade-format to re-seal as SFSE2, see master finding #10)\n", "upgradable:", n)
	}

	if len(report.Problems) == 0 {
		fmt.Fprintln(w, "\nNo problems found.")
		return
	}

	fmt.Fprintln(w, "\nProblems:")
	for _, p := range report.Problems {
		fmt.Fprintf(w, "  claim=%s file=%s db_size=%d disk_size=%d: %s\n",
			p.ClaimCodePrefix, p.StoredFilename, p.DBSize, p.DiskSize, p.Issue)
	}
}

// openReadOnlyDB opens the SQLite database so that SQLite itself refuses
// writes: --verify must never modify a production database, even by accident.
//
// The DSN must be a "file:" URI: with a bare path, the driver silently
// ignores "?mode=ro" and opens read-write. query_only is a second guard.
func openReadOnlyDB(dbPath string) (*sql.DB, error) {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, err
	}
	dsn := (&url.URL{
		Scheme:   "file",
		Path:     abs,
		RawQuery: "mode=ro&_pragma=query_only(1)",
	}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
