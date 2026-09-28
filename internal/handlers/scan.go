package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/scanning"
)

// malwareScanner is the subset of *scanning.ClamAVScanner used by scanUpload.
// Tests substitute a fake via newScanner.
type malwareScanner interface {
	ScanReader(ctx context.Context, r io.Reader, size int64) (*scanning.ScanResult, error)
}

// newScanner constructs the scanner used for uploads. Overridden in tests to
// inject a fake clamd (see internal/scanning/scanningtest).
var newScanner = func(cfg *config.Config) malwareScanner {
	return scanning.NewClamAVScanner(
		cfg.ClamAV.Host,
		cfg.ClamAV.Port,
		time.Duration(cfg.ClamAV.Timeout)*time.Second,
		time.Duration(cfg.ClamAV.ScanTimeout)*time.Second,
		cfg.ClamAV.MaxFileSize,
	)
}

// scanVerdict is the outcome of scanUpload: the scan_status/scan_result pair
// to persist on the file record. A zero-value verdict (status == "") means
// scanning is disabled and the columns should stay NULL, matching legacy
// (pre-ADR-015) rows.
type scanVerdict struct {
	status string
	result string
	// hash is the hex-encoded SHA-256 of exactly the bytes scanUpload read
	// from r. Empty when nothing was actually read (scanning disabled, or
	// content skipped for exceeding the scan size limit — see
	// scanning.ScanResult.Skipped). Callers that later re-read the same
	// logical content from a separate source (in particular the chunked
	// upload path re-reading chunk files from disk during assembly) MUST
	// compare this against a fresh hash of what they actually stored/
	// assembled whenever it's non-empty: chunk files on disk between the
	// scan and the assembly step are exactly the kind of mutable state a
	// TOCTOU attack can rewrite (bug-hunter finding — see
	// assembly_worker.go's post-assembly integrity check).
	hash string
}

// scanUpload synchronously scans r for malware and returns the verdict to
// persist on the file record. It must be called BEFORE the file is
// encrypted/stored and BEFORE a claim code is generated or returned
// (ADR-015): scanning ciphertext or handing out a claim code ahead of the
// verdict is exactly the bug this design closes. r must yield the ORIGINAL
// uploaded bytes — before metadata stripping, before encryption.
//
// Returns a zero scanVerdict, nil when malware scanning is disabled.
// Returns a non-nil error only when the scan itself could not be completed
// (clamd unreachable, timed out, or returned something this client couldn't
// parse) — callers decide whether that blocks the upload
// (MALWARE_SCAN_ALLOW_UNVERIFIED).
//
// clientEncrypted content is untrusted (the server cannot know it's really
// E2E ciphertext), so it is always scanned — an attacker could smuggle
// plaintext malware through the client_encrypted flag — but a non-infected
// result is reported as "not_scanned" rather than "clean": the server has no
// way to verify genuine ciphertext is actually harmless once decrypted
// client-side.
func scanUpload(ctx context.Context, cfg *config.Config, r io.Reader, size int64, clientEncrypted bool) (scanVerdict, error) {
	if !cfg.Features.IsMalwareScanEnabled() {
		return scanVerdict{}, nil
	}

	// Hash exactly what gets scanned so callers can detect content swapped
	// out from under them before a later re-read (bug-hunter finding: see
	// the scanVerdict.hash doc comment).
	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)

	scanner := newScanner(cfg)
	result, err := scanner.ScanReader(ctx, tee, size)
	if err != nil {
		return scanVerdict{}, err
	}

	// Skipped (oversize) content is never actually read by ScanReader — the
	// size check happens before any bytes are pulled through the tee — so
	// the hash would be the empty-input hash, not a hash of the real
	// content. Leave it unset; there is nothing to compare against later.
	var hash string
	if !result.Skipped {
		hash = hex.EncodeToString(hasher.Sum(nil))
	}

	if result.Infected {
		return scanVerdict{status: scanning.ScanStatusInfected, result: result.VirusName, hash: hash}, nil
	}

	if result.Skipped {
		return scanVerdict{status: scanning.ScanStatusNotScanned, result: "exceeds scan size limit"}, nil
	}

	if clientEncrypted {
		return scanVerdict{status: scanning.ScanStatusNotScanned, result: "client_encrypted", hash: hash}, nil
	}

	return scanVerdict{status: scanning.ScanStatusClean, result: "", hash: hash}, nil
}
