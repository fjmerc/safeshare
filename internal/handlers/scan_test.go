package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/scanning"
	"github.com/fjmerc/safeshare/internal/scanning/scanningtest"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// testEncryptionKey is a valid 64-hex-char (32 byte) AES-256 key, matching
// the literal used elsewhere in this package's tests.
const testEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// assembleUploadSync replaces the pre-ADR-016 AssembleUploadAsync(repos,
// cfg, upload, clientIP) call these tests used: it locks the upload for
// processing (as UploadCompleteHandler would) and then runs the assembly
// pipeline synchronously in the calling goroutine, so a plain function call
// in a test still deterministically waits for the result.
func assembleUploadSync(t *testing.T, repos *repository.Repositories, cfg *config.Config, upload *models.PartialUpload) {
	t.Helper()
	lease := repository.AssemblyLease{Owner: "test-owner-" + upload.UploadID, TTL: time.Minute}
	locked, err := repos.PartialUploads.TryLockForProcessing(context.Background(), upload.UploadID, lease)
	if err != nil {
		t.Fatalf("TryLockForProcessing: %v", err)
	}
	if !locked {
		t.Fatalf("TryLockForProcessing: expected to acquire lock for %s", upload.UploadID)
	}
	runAssembly(repos, cfg, upload, lease)
}

// enableMalwareScan points cfg at a fake clamd server and enables the
// malware scanning feature flag.
func enableMalwareScan(cfg *config.Config, srv *scanningtest.Server) {
	cfg.Features.SetMalwareScanEnabled(true)
	cfg.ClamAV.Host = srv.Host
	cfg.ClamAV.Port = srv.Port
	cfg.ClamAV.Timeout = 5
	cfg.ClamAV.ScanTimeout = 5
	cfg.ClamAV.MaxFileSize = 10 * 1024 * 1024
}

// TestScanUpload_Disabled verifies scanUpload is a no-op (zero verdict, nil
// error) when the malware scan feature flag is off — scanUpload must not
// even attempt to dial clamd in this case.
func TestScanUpload_Disabled(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)
	// Deliberately unreachable: the test fails loudly (dial error surfacing
	// as scanUpload's returned error) if scanUpload tries to connect despite
	// the feature being disabled.
	cfg.ClamAV.Host = "192.0.2.1"
	cfg.ClamAV.Port = 3310
	cfg.ClamAV.Timeout = 1

	verdict, err := scanUpload(context.Background(), cfg, strings.NewReader("hello"), 5, false)
	if err != nil {
		t.Fatalf("scanUpload() unexpected error: %v", err)
	}
	if verdict.status != "" || verdict.result != "" {
		t.Errorf("scanUpload() verdict = %+v, want zero value", verdict)
	}
}

// TestScanUpload_CleanInfectedAndE2E covers the core scanUpload decision
// table directly (no HTTP layer) against a fake clamd.
func TestScanUpload_CleanInfectedAndE2E(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	cfg := testutil.SetupTestConfig(t)
	enableMalwareScan(cfg, srv)

	tests := []struct {
		name            string
		content         string
		clientEncrypted bool
		wantStatus      string
		wantResult      string
	}{
		{"clean", "just an ordinary file", false, scanning.ScanStatusClean, ""},
		{"infected", scanningtest.EICARString, false, scanning.ScanStatusInfected, "Eicar-Test-Signature"},
		{"e2e clean content reported not_scanned", "just an ordinary file", true, scanning.ScanStatusNotScanned, "client_encrypted"},
		{"e2e infected content still detected", scanningtest.EICARString, true, scanning.ScanStatusInfected, "Eicar-Test-Signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verdict, err := scanUpload(context.Background(), cfg, strings.NewReader(tt.content), int64(len(tt.content)), tt.clientEncrypted)
			if err != nil {
				t.Fatalf("scanUpload() unexpected error: %v", err)
			}
			if verdict.status != tt.wantStatus {
				t.Errorf("status = %q, want %q", verdict.status, tt.wantStatus)
			}
			if verdict.result != tt.wantResult {
				t.Errorf("result = %q, want %q", verdict.result, tt.wantResult)
			}
		})
	}
}

// TestScanUpload_Oversized verifies content over CLAMAV_MAX_FILE_SIZE is
// reported not_scanned rather than clean, and never dials clamd.
func TestScanUpload_Oversized(t *testing.T) {
	cfg := testutil.SetupTestConfig(t)
	cfg.Features.SetMalwareScanEnabled(true)
	cfg.ClamAV.Host = "192.0.2.1" // unreachable; must never be dialed
	cfg.ClamAV.Port = 3310
	cfg.ClamAV.Timeout = 1
	cfg.ClamAV.MaxFileSize = 1

	verdict, err := scanUpload(context.Background(), cfg, strings.NewReader("more than one byte"), 19, false)
	if err != nil {
		t.Fatalf("scanUpload() unexpected error: %v", err)
	}
	if verdict.status != scanning.ScanStatusNotScanned {
		t.Errorf("status = %q, want %q", verdict.status, scanning.ScanStatusNotScanned)
	}
}

// TestUploadHandler_MalwareDetected verifies an EICAR upload with
// ENCRYPTION_KEY set is rejected before storage, with no claim code
// returned and an infected audit row created.
func TestUploadHandler_MalwareDetected(t *testing.T) {
	for _, stripMetadata := range []bool{false, true} {
		t.Run(fmt.Sprintf("strip_metadata=%v", stripMetadata), func(t *testing.T) {
			srv := scanningtest.New(t, scanningtest.ModeNormal)
			db := testutil.SetupTestDB(t)
			cfg := testutil.SetupTestConfig(t)
			cfg.EncryptionKey = testEncryptionKey
			cfg.StripMetadata = stripMetadata
			enableMalwareScan(cfg, srv)

			repos, err := sqlite.NewRepositories(cfg, db)
			if err != nil {
				t.Fatalf("failed to create repositories: %v", err)
			}
			handler := UploadHandler(repos, cfg)

			body, contentType := testutil.CreateMultipartForm(t, []byte(scanningtest.EICARString), "eicar.txt", nil)
			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, http.StatusUnprocessableEntity)

			var errResp models.ErrorResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("failed to decode error response: %v", err)
			}
			if errResp.Code != "MALWARE_DETECTED" {
				t.Errorf("error code = %q, want MALWARE_DETECTED", errResp.Code)
			}
			if strings.Contains(rr.Body.String(), "claim_code") {
				t.Error("response must not contain a claim code for an infected upload")
			}

			// No file should have been written to the uploads directory.
			entries, _ := os.ReadDir(cfg.UploadDir)
			for _, e := range entries {
				if !strings.HasPrefix(e.Name(), ".") {
					t.Errorf("unexpected file written to uploads dir for infected upload: %s", e.Name())
				}
			}

			// An audit row should exist, marked infected, with no claim code
			// ever surfaced to a client.
			files, total, err := repos.Files.GetAllForAdmin(context.Background(), 10, 0)
			if err != nil {
				t.Fatalf("GetAllForAdmin() error: %v", err)
			}
			if total != 1 {
				t.Fatalf("total files = %d, want 1", total)
			}
			if files[0].ScanStatus != scanning.ScanStatusInfected {
				t.Errorf("ScanStatus = %q, want infected", files[0].ScanStatus)
			}
			if files[0].ScanResult != "Eicar-Test-Signature" {
				t.Errorf("ScanResult = %q, want Eicar-Test-Signature", files[0].ScanResult)
			}
		})
	}
}

// TestUploadHandler_ScanClean_EncryptedRoundtrip verifies a clean upload
// under ENCRYPTION_KEY is stored as ciphertext (SFSE2) that decrypts back to
// the original plaintext, with scan_status=clean.
func TestUploadHandler_ScanClean_EncryptedRoundtrip(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testEncryptionKey
	enableMalwareScan(cfg, srv)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := UploadHandler(repos, cfg)

	plaintext := []byte("perfectly ordinary, harmless file content")
	body, contentType := testutil.CreateMultipartForm(t, plaintext, "clean.txt", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.UploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	file, err := repos.Files.GetByClaimCode(context.Background(), resp.ClaimCode)
	if err != nil || file == nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}
	if file.ScanStatus != scanning.ScanStatusClean {
		t.Errorf("ScanStatus = %q, want clean", file.ScanStatus)
	}

	storedPath := filepath.Join(cfg.UploadDir, file.StoredFilename)
	onDisk, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatalf("failed to read stored file: %v", err)
	}
	if bytes.Contains(onDisk, plaintext) {
		t.Error("stored file appears to contain plaintext; expected SFSE2 ciphertext")
	}

	decPath := storedPath + ".dec"
	defer os.Remove(decPath)
	if err := utils.DecryptFileStreamingAny(storedPath, decPath, cfg.EncryptionKey, file.EncFileID, "", file.FileSize); err != nil {
		t.Fatalf("failed to decrypt stored file: %v", err)
	}
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted content = %q, want %q", decrypted, plaintext)
	}
}

// TestUploadHandler_ScanUnavailable verifies an unreachable clamd fails the
// upload by default (503 SCAN_UNAVAILABLE), and that
// MALWARE_SCAN_ALLOW_UNVERIFIED lets the upload proceed with scan_status=error.
func TestUploadHandler_ScanUnavailable(t *testing.T) {
	for _, allowUnverified := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_unverified=%v", allowUnverified), func(t *testing.T) {
			db := testutil.SetupTestDB(t)
			cfg := testutil.SetupTestConfig(t)
			cfg.Features.SetMalwareScanEnabled(true)
			cfg.ClamAV.Host = "192.0.2.1" // TEST-NET-1: never routable, dial fails fast on most stacks
			cfg.ClamAV.Port = 3310
			cfg.ClamAV.Timeout = 1
			cfg.ClamAV.AllowUnverified = allowUnverified

			repos, err := sqlite.NewRepositories(cfg, db)
			if err != nil {
				t.Fatalf("failed to create repositories: %v", err)
			}
			handler := UploadHandler(repos, cfg)

			body, contentType := testutil.CreateMultipartForm(t, []byte("hello"), "test.txt", nil)
			req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
			req.Header.Set("Content-Type", contentType)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if !allowUnverified {
				testutil.AssertStatusCode(t, rr, http.StatusServiceUnavailable)
				if rr.Header().Get("Retry-After") == "" {
					t.Error("expected Retry-After header on SCAN_UNAVAILABLE")
				}
				return
			}

			testutil.AssertStatusCode(t, rr, http.StatusCreated)
			var resp models.UploadResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			file, err := repos.Files.GetByClaimCode(context.Background(), resp.ClaimCode)
			if err != nil || file == nil {
				t.Fatalf("GetByClaimCode() error: %v", err)
			}
			if file.ScanStatus != scanning.ScanStatusError {
				t.Errorf("ScanStatus = %q, want error", file.ScanStatus)
			}
		})
	}
}

// TestUploadHandler_ScanDisabled verifies scan_status stays unset (NULL) and
// the upload succeeds normally when the feature flag is off.
func TestUploadHandler_ScanDisabled(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	// Feature left disabled (default). Point at an unreachable host so the
	// test fails loudly if scanning is attempted anyway.
	cfg.ClamAV.Host = "192.0.2.1"
	cfg.ClamAV.Port = 3310
	cfg.ClamAV.Timeout = 1

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := UploadHandler(repos, cfg)

	body, contentType := testutil.CreateMultipartForm(t, []byte("hello"), "test.txt", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.UploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	file, err := repos.Files.GetByClaimCode(context.Background(), resp.ClaimCode)
	if err != nil || file == nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}
	if file.ScanStatus != "" {
		t.Errorf("ScanStatus = %q, want empty (scanning disabled)", file.ScanStatus)
	}
}

// TestUploadHandler_RejectUnscannable verifies MALWARE_SCAN_REJECT_UNSCANNABLE
// rejects an E2E-encrypted upload outright with 422 UNSCANNABLE_UPLOAD.
func TestUploadHandler_RejectUnscannable(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	enableMalwareScan(cfg, srv)
	cfg.ClamAV.RejectUnscannable = true

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := UploadHandler(repos, cfg)

	body, contentType := testutil.CreateMultipartForm(t, []byte("opaque ciphertext"), "blob.bin", map[string]string{
		"client_encrypted": "true",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnprocessableEntity)
	var errResp models.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != "UNSCANNABLE_UPLOAD" {
		t.Errorf("error code = %q, want UNSCANNABLE_UPLOAD", errResp.Code)
	}
}

// TestUploadInitHandler_RejectUnscannable verifies the same
// MALWARE_SCAN_REJECT_UNSCANNABLE gate applies at chunked-upload init.
func TestUploadInitHandler_RejectUnscannable(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	enableMalwareScan(cfg, srv)
	cfg.ClamAV.RejectUnscannable = true

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := UploadInitHandler(repos, cfg)

	reqBody := `{"filename":"blob.bin","total_size":2048,"client_encrypted":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnprocessableEntity)
	var errResp models.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp.Code != "UNSCANNABLE_UPLOAD" {
		t.Errorf("error code = %q, want UNSCANNABLE_UPLOAD", errResp.Code)
	}
}

// TestAssembleUploadAsync_MalwareDetected verifies a chunked upload whose
// content contains the EICAR string fails assembly with error_code
// MALWARE_DETECTED, and never produces a claim code or a stored file.
func TestAssembleUploadAsync_MalwareDetected(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testEncryptionKey
	enableMalwareScan(cfg, srv)
	// No retries needed for this test; keep it fast regardless.
	origBackoff := scanRetryBackoff
	scanRetryBackoff = nil
	t.Cleanup(func() { scanRetryBackoff = origBackoff })

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	uploadID := "550e8400-e29b-41d4-a716-446655440099"
	content := []byte(scanningtest.EICARString)
	partialUpload := &models.PartialUpload{
		UploadID:       uploadID,
		Filename:       "eicar.bin",
		TotalSize:      int64(len(content)),
		ChunkSize:      int64(len(content)),
		TotalChunks:    1,
		ExpiresInHours: 24,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}
	ctx := context.Background()
	if err := repos.PartialUploads.Create(ctx, partialUpload); err != nil {
		t.Fatalf("failed to create partial upload: %v", err)
	}

	if err := utils.SaveChunk(cfg.UploadDir, uploadID, 0, content); err != nil {
		t.Fatalf("failed to save chunk: %v", err)
	}

	assembleUploadSync(t, repos, cfg, partialUpload)

	result, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetByUploadID() error: %v", err)
	}
	if result.Status != "failed" {
		t.Fatalf("status = %q, want failed", result.Status)
	}
	if result.ErrorCode == nil || *result.ErrorCode != "MALWARE_DETECTED" {
		t.Errorf("error_code = %v, want MALWARE_DETECTED", result.ErrorCode)
	}
	if result.ClaimCode != nil {
		t.Error("expected no claim code for an infected chunked upload")
	}

	entries, _ := os.ReadDir(cfg.UploadDir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			t.Errorf("unexpected file written to uploads dir for infected chunked upload: %s", e.Name())
		}
	}
}

// TestClaimHandler_ScanGate covers the download gate's per-status behaviour
// for a seeded file row, including that a blocked request never creates a
// download_sessions row.
func TestClaimHandler_ScanGate(t *testing.T) {
	tests := []struct {
		name            string
		scanStatus      string
		allowUnverified bool
		wantStatus      int
		wantCode        string
	}{
		{"infected always blocked", scanning.ScanStatusInfected, false, http.StatusGone, "FILE_QUARANTINED"},
		{"infected blocked even with allow_unverified", scanning.ScanStatusInfected, true, http.StatusGone, "FILE_QUARANTINED"},
		{"pending blocked by default", scanning.ScanStatusPending, false, http.StatusLocked, "SCAN_PENDING"},
		{"pending allowed with allow_unverified", scanning.ScanStatusPending, true, http.StatusOK, ""},
		{"error blocked by default", scanning.ScanStatusError, false, http.StatusForbidden, "SCAN_FAILED"},
		{"error allowed with allow_unverified", scanning.ScanStatusError, true, http.StatusOK, ""},
		{"clean allowed", scanning.ScanStatusClean, false, http.StatusOK, ""},
		{"not_scanned allowed", scanning.ScanStatusNotScanned, false, http.StatusOK, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := testutil.SetupTestDB(t)
			cfg := testutil.SetupTestConfig(t)
			cfg.ClamAV.AllowUnverified = tt.allowUnverified
			repos, err := sqlite.NewRepositories(cfg, db)
			if err != nil {
				t.Fatalf("failed to create repositories: %v", err)
			}

			content := []byte("some file content")
			storedFilename := "gate-test.txt"
			if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			claimCode := "gatecode" + tt.scanStatus + fmt.Sprintf("%v", tt.allowUnverified)
			maxDownloads := 5
			file := &models.File{
				ClaimCode:        claimCode,
				OriginalFilename: "gate-test.txt",
				StoredFilename:   storedFilename,
				FileSize:         int64(len(content)),
				MimeType:         "text/plain",
				ExpiresAt:        time.Now().Add(24 * time.Hour),
				MaxDownloads:     &maxDownloads, // capped, so a blocked request would otherwise create a session row
				ScanStatus:       tt.scanStatus,
			}
			ctx := context.Background()
			if err := repos.Files.Create(ctx, file); err != nil {
				t.Fatalf("failed to create file record: %v", err)
			}

			handler := ClaimHandler(repos, cfg)
			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+claimCode, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantStatus)

			if tt.wantCode != "" {
				var errResp models.ErrorResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if errResp.Code != tt.wantCode {
					t.Errorf("error code = %q, want %q", errResp.Code, tt.wantCode)
				}

				// A blocked request must never reserve/commit a download
				// session against the file's cap.
				var sessionCount int
				if err := db.QueryRow("SELECT COUNT(*) FROM download_sessions WHERE file_id = ?", file.ID).Scan(&sessionCount); err != nil {
					t.Fatalf("failed to count download_sessions: %v", err)
				}
				if sessionCount != 0 {
					t.Errorf("download_sessions rows for blocked file = %d, want 0", sessionCount)
				}
			}
		})
	}
}

// TestInfectedAuditRow_DoesNotExhaustQuota is a regression test for the
// bug-hunter finding that recordInfectedUpload/recordInfectedChunkedUpload
// used to store the uploader's declared FileSize (and the uploader's
// requested, possibly-never expiry) on the audit row, letting repeated
// EICAR uploads near the size limit permanently exhaust the quota with zero
// real disk usage. This exercises the query-level defense-in-depth
// exclusion directly: even a row that (by some future bug) still carries a
// large FileSize must not count against the quota once ScanStatus is
// "infected".
func TestInfectedAuditRow_DoesNotExhaustQuota(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	const quotaBytes = 200 * 1024 * 1024 // 200MB

	// Simulate several "infected" audit rows that (hypothetically) still
	// carry a large declared size — the defense-in-depth query exclusion
	// must ignore them regardless.
	for i := 0; i < 5; i++ {
		infected := &models.File{
			ClaimCode:        fmt.Sprintf("infected-%d", i),
			OriginalFilename: "eicar.txt",
			StoredFilename:   fmt.Sprintf("quarantined-%d", i),
			FileSize:         190 * 1024 * 1024, // would alone nearly exhaust the quota
			MimeType:         "application/octet-stream",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			ScanStatus:       scanning.ScanStatusInfected,
			ScanResult:       "Eicar-Test-Signature",
		}
		if err := repos.Files.Create(ctx, infected); err != nil {
			t.Fatalf("failed to create infected row %d: %v", i, err)
		}
	}

	// A legitimate 100MB upload must still fit under a 200MB quota — it
	// would not if any of the five 190MB infected rows above counted.
	legit := &models.File{
		ClaimCode:        "legit-upload",
		OriginalFilename: "document.pdf",
		StoredFilename:   "real-file.pdf",
		FileSize:         100 * 1024 * 1024,
		MimeType:         "application/pdf",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	if err := repos.Files.CreateWithQuotaCheck(ctx, legit, quotaBytes); err != nil {
		t.Fatalf("CreateWithQuotaCheck() error = %v, want legitimate upload to succeed despite prior infected rows", err)
	}

	// GetTotalUsage must also ignore the infected rows.
	usage, err := repos.Files.GetTotalUsage(ctx)
	if err != nil {
		t.Fatalf("GetTotalUsage() error: %v", err)
	}
	if usage != 100*1024*1024 {
		t.Errorf("GetTotalUsage() = %d, want %d (infected rows must not count)", usage, 100*1024*1024)
	}
}

// TestGetStats_ExcludesInfectedRowsFromStorage verifies GetStats counts
// infected audit rows toward TotalFiles but never toward StorageUsed.
func TestGetStats_ExcludesInfectedRowsFromStorage(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	infected := &models.File{
		ClaimCode:        "infected-stats",
		OriginalFilename: "eicar.txt",
		StoredFilename:   "quarantined-stats",
		FileSize:         500 * 1024 * 1024,
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		ScanStatus:       scanning.ScanStatusInfected,
	}
	if err := repos.Files.Create(ctx, infected); err != nil {
		t.Fatalf("failed to create infected row: %v", err)
	}

	normal := &models.File{
		ClaimCode:        "normal-stats",
		OriginalFilename: "document.pdf",
		StoredFilename:   "real-stats.pdf",
		FileSize:         10 * 1024 * 1024,
		MimeType:         "application/pdf",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	if err := repos.Files.Create(ctx, normal); err != nil {
		t.Fatalf("failed to create normal row: %v", err)
	}

	stats, err := repos.Files.GetStats(ctx, cfg.UploadDir)
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}
	if stats.TotalFiles != 2 {
		t.Errorf("TotalFiles = %d, want 2 (infected rows still count as files)", stats.TotalFiles)
	}
	if stats.StorageUsed != 10*1024*1024 {
		t.Errorf("StorageUsed = %d, want %d (infected row's declared size must not count)", stats.StorageUsed, 10*1024*1024)
	}
}

// TestUploadHandler_InfectedAuditRow_BoundedExpiry verifies an infected
// audit row's expiry is bounded to the server default even when the
// uploader requested expires_in_hours=0 ("never expire").
func TestUploadHandler_InfectedAuditRow_BoundedExpiry(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	enableMalwareScan(cfg, srv)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := UploadHandler(repos, cfg)

	body, contentType := testutil.CreateMultipartForm(t, []byte(scanningtest.EICARString), "eicar.txt", map[string]string{
		"expires_in_hours": "0", // "never expire"
	})
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusUnprocessableEntity)

	files, total, err := repos.Files.GetAllForAdmin(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("GetAllForAdmin() error: %v", err)
	}
	if total != 1 {
		t.Fatalf("total files = %d, want 1", total)
	}

	maxBound := time.Now().Add(time.Duration(cfg.GetDefaultExpirationHours())*time.Hour + time.Hour)
	if files[0].ExpiresAt.After(maxBound) {
		t.Errorf("infected audit row ExpiresAt = %v, want bounded near now+%dh (uploader's neverExpire request must be ignored)",
			files[0].ExpiresAt, cfg.GetDefaultExpirationHours())
	}
	if files[0].FileSize != 0 {
		t.Errorf("infected audit row FileSize = %d, want 0", files[0].FileSize)
	}
}

// TestAssembleUploadAsync_EncryptedFastPath_SizeMismatchIsTerminal is a
// code-review regression test: the encrypted-no-strip fast path
// (utils.AssembleChunksEncrypted) never verified the assembled byte count
// against the declared TotalSize, unlike the multi-pass path a few lines
// below it — a chunk shrunk on disk between /complete's preflight checks and
// this reopen surfaced (if at all) as the generic, retryable ASSEMBLY_FAILED
// instead of a terminal INTEGRITY_ERROR. Chunks are only checked for
// presence (GetMissingChunks), not size, before assembly starts.
func TestAssembleUploadAsync_EncryptedFastPath_SizeMismatchIsTerminal(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testEncryptionKey // encryption on, no metadata stripping -> fast path

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	uploadID := "550e8400-e29b-41d4-a716-446655440082"
	// Declares 1024 bytes across 2 chunks but only 768 are actually written
	// (chunk 1 truncated).
	partialUpload := &models.PartialUpload{
		UploadID: uploadID, Filename: "test.bin", TotalSize: 1024, ChunkSize: 512,
		TotalChunks: 2, ExpiresInHours: 24, CreatedAt: time.Now(), LastActivity: time.Now(),
	}
	ctx := context.Background()
	if err := repos.PartialUploads.Create(ctx, partialUpload); err != nil {
		t.Fatalf("failed to create partial upload: %v", err)
	}
	if err := utils.SaveChunk(cfg.UploadDir, uploadID, 0, bytes.Repeat([]byte("a"), 512)); err != nil {
		t.Fatalf("failed to save chunk 0: %v", err)
	}
	if err := utils.SaveChunk(cfg.UploadDir, uploadID, 1, bytes.Repeat([]byte("b"), 256)); err != nil {
		t.Fatalf("failed to save chunk 1: %v", err)
	}

	assembleUploadSync(t, repos, cfg, partialUpload)

	result, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetByUploadID() error: %v", err)
	}
	if result.Status != "failed" {
		t.Fatalf("status = %q, want failed", result.Status)
	}
	if result.ErrorCode == nil || *result.ErrorCode != "INTEGRITY_ERROR" {
		t.Errorf("error_code = %v, want INTEGRITY_ERROR", result.ErrorCode)
	}
	if result.ErrorRetryable {
		t.Error("expected INTEGRITY_ERROR to be non-retryable (attempts must not be silently retried)")
	}
	if result.ClaimCode != nil {
		t.Error("expected no claim code for a size-mismatched assembly")
	}

	entries, _ := os.ReadDir(cfg.UploadDir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			t.Errorf("unexpected file left in uploads dir after failed assembly: %s", e.Name())
		}
	}
}

// TestAssembleUploadAsync_MissingChunkFailsFast verifies a missing chunk
// file fails assembly immediately with error_code ASSEMBLY_FAILED — not
// SCAN_UNAVAILABLE, and without going through the 3x scan-retry backoff
// (bug-hunter finding: a missing chunk is a data problem, not a transient
// scanner problem).
func TestAssembleUploadAsync_MissingChunkFailsFast(t *testing.T) {
	// A reachable fake clamd, so the scan actually gets as far as streaming
	// chunk content (and therefore hits the missing chunk) instead of
	// failing earlier at connect() — which would exercise the ordinary
	// SCAN_UNAVAILABLE retry path instead of the one this test targets.
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	enableMalwareScan(cfg, srv)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	uploadID := "550e8400-e29b-41d4-a716-446655440077"
	partialUpload := &models.PartialUpload{
		UploadID:       uploadID,
		Filename:       "test.bin",
		TotalSize:      1024,
		ChunkSize:      512,
		TotalChunks:    2,
		ExpiresInHours: 24,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}
	ctx := context.Background()
	if err := repos.PartialUploads.Create(ctx, partialUpload); err != nil {
		t.Fatalf("failed to create partial upload: %v", err)
	}
	// Chunk 0 exists (so MIME detection, which only reads chunk 0, succeeds);
	// chunk 1 is deliberately missing so the scan step's chunk reader fails
	// partway through, exercising OpenChunksReader/scanChunkedUploadWithRetry
	// rather than the earlier MIME-detection open.
	if err := utils.SaveChunk(cfg.UploadDir, uploadID, 0, bytes.Repeat([]byte("a"), 512)); err != nil {
		t.Fatalf("failed to save chunk 0: %v", err)
	}

	start := time.Now()
	assembleUploadSync(t, repos, cfg, partialUpload)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("AssembleUploadAsync() took %v for a missing chunk, want near-instant (no retry backoff)", elapsed)
	}

	result, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetByUploadID() error: %v", err)
	}
	if result.Status != "failed" {
		t.Fatalf("status = %q, want failed", result.Status)
	}
	if result.ErrorCode == nil || *result.ErrorCode != "ASSEMBLY_FAILED" {
		t.Errorf("error_code = %v, want ASSEMBLY_FAILED", result.ErrorCode)
	}
	// Bug-hunter follow-up finding: a missing chunk is structurally
	// unrecoverable — /complete 400s MISSING_CHUNKS before ever reaching
	// the lock, and chunk PUTs are refused once status is no longer
	// "uploading" — so this must NOT be flagged retryable (there is no
	// path back to a retry ever succeeding).
	if result.ErrorRetryable {
		t.Error("expected a missing-chunk failure to be non-retryable (no recovery path exists)")
	}
}

// toctouScanner wraps a real scanner and, immediately after a successful
// scan, overwrites a chunk file on disk with different (same-size) content —
// simulating the race a malicious uploader could win by re-sending a chunk
// while /complete is in flight: the version scanned is not the version later
// reopened for assembly.
type toctouScanner struct {
	real        malwareScanner
	uploadDir   string
	uploadID    string
	swapChunk   int
	swapContent []byte
}

func (s *toctouScanner) ScanReader(ctx context.Context, r io.Reader, size int64) (*scanning.ScanResult, error) {
	result, err := s.real.ScanReader(ctx, r, size)
	if err == nil {
		if saveErr := utils.SaveChunk(s.uploadDir, s.uploadID, s.swapChunk, s.swapContent); saveErr != nil {
			panic(fmt.Sprintf("toctouScanner: failed to swap chunk: %v", saveErr))
		}
	}
	return result, err
}

// TestAssembleUploadAsync_TOCTOU_RejectsSwappedContent is a regression test
// for the bug-hunter finding that a chunk rewritten on disk between the
// synchronous scan and the assembly step could publish content that was
// never actually scanned: UploadChunkHandler's re-upload path isn't atomic
// with /complete's TryLockForProcessing, so a same-size chunk 0 re-sent
// while assembly is starting can land after the scan already read the old
// (benign) bytes but before AssembleChunks/AssembleChunksEncrypted reopens
// the file. Covers both assembly branches (plaintext multi-pass and the
// encrypted fast path).
func TestAssembleUploadAsync_TOCTOU_RejectsSwappedContent(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%v", encrypted), func(t *testing.T) {
			srv := scanningtest.New(t, scanningtest.ModeNormal)
			db := testutil.SetupTestDB(t)
			cfg := testutil.SetupTestConfig(t)
			enableMalwareScan(cfg, srv)
			if encrypted {
				cfg.EncryptionKey = testEncryptionKey
			}

			repos, err := sqlite.NewRepositories(cfg, db)
			if err != nil {
				t.Fatalf("failed to create repositories: %v", err)
			}

			uploadID := fmt.Sprintf("550e8400-e29b-41d4-a716-4466554400%02d", map[bool]int{false: 80, true: 81}[encrypted])
			chunk0 := bytes.Repeat([]byte("a"), 512) // what gets scanned
			chunk1 := bytes.Repeat([]byte("b"), 512)
			partialUpload := &models.PartialUpload{
				UploadID:       uploadID,
				Filename:       "test.bin",
				TotalSize:      1024,
				ChunkSize:      512,
				TotalChunks:    2,
				ExpiresInHours: 24,
				CreatedAt:      time.Now(),
				LastActivity:   time.Now(),
			}
			ctx := context.Background()
			if err := repos.PartialUploads.Create(ctx, partialUpload); err != nil {
				t.Fatalf("failed to create partial upload: %v", err)
			}
			if err := utils.SaveChunk(cfg.UploadDir, uploadID, 0, chunk0); err != nil {
				t.Fatalf("failed to save chunk 0: %v", err)
			}
			if err := utils.SaveChunk(cfg.UploadDir, uploadID, 1, chunk1); err != nil {
				t.Fatalf("failed to save chunk 1: %v", err)
			}

			// Same size as chunk0 (1024 total still matches TotalSize, so this
			// isn't caught by the pre-existing size-mismatch check) but
			// different content — what actually gets assembled.
			malicious := bytes.Repeat([]byte("X"), 512)

			realScanner := scanning.NewClamAVScanner(srv.Host, srv.Port, 5*time.Second, 5*time.Second, cfg.ClamAV.MaxFileSize)
			origNewScanner := newScanner
			newScanner = func(cfg *config.Config) malwareScanner {
				return &toctouScanner{
					real:        realScanner,
					uploadDir:   cfg.UploadDir,
					uploadID:    uploadID,
					swapChunk:   0,
					swapContent: malicious,
				}
			}
			t.Cleanup(func() { newScanner = origNewScanner })

			assembleUploadSync(t, repos, cfg, partialUpload)

			result, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
			if err != nil {
				t.Fatalf("GetByUploadID() error: %v", err)
			}
			if result.Status != "failed" {
				t.Fatalf("status = %q, want failed", result.Status)
			}
			// ADR-016: a TOCTOU content mismatch is now its own terminal
			// error_code (INTEGRITY_ERROR) rather than the generic,
			// retryable ASSEMBLY_FAILED — retrying can't fix a race that
			// already happened.
			if result.ErrorCode == nil || *result.ErrorCode != "INTEGRITY_ERROR" {
				t.Errorf("error_code = %v, want INTEGRITY_ERROR", result.ErrorCode)
			}
			if result.ErrorRetryable {
				t.Error("expected INTEGRITY_ERROR to be non-retryable")
			}
			if result.ClaimCode != nil {
				t.Error("expected no claim code when scanned/assembled content mismatch")
			}

			// No file record — a clean verdict on stale content must never be
			// published, under either name.
			_, total, err := repos.Files.GetAllForAdmin(ctx, 10, 0)
			if err != nil {
				t.Fatalf("GetAllForAdmin() error: %v", err)
			}
			if total != 0 {
				t.Errorf("published file rows = %d, want 0 (a content mismatch must never be published)", total)
			}

			// No stray output file left on disk either.
			entries, _ := os.ReadDir(cfg.UploadDir)
			for _, e := range entries {
				if !strings.HasPrefix(e.Name(), ".") {
					t.Errorf("unexpected file left in uploads dir after rejected assembly: %s", e.Name())
				}
			}
		})
	}
}

// TestAssembleUploadAsync_ShutdownDuringScan_LeavesUploadForRecovery is a
// bug-hunter regression test (ADR-016 M1): closing the clamd connection on
// shutdown (scanner.go's ctx-watcher goroutine) surfaces to the caller as a
// generic "use of closed network connection" error, not context.Canceled —
// pattern-matching the scan error to detect an abort is unreliable. The
// worker must instead check w.aborted() directly, or a shutdown/lease-loss
// mid-scan gets misrecorded as a terminal-looking SCAN_UNAVAILABLE failure
// (burning a retry attempt) instead of being left in "processing" for
// recovery to pick straight back up.
func TestAssembleUploadAsync_ShutdownDuringScan_LeavesUploadForRecovery(t *testing.T) {
	// ModeHang: clamd accepts the connection and reads the full stream, but
	// never replies — the worker blocks in scanner.go's readResponse until
	// something closes the socket, exactly the window CancelAssemblies must
	// interrupt.
	srv := scanningtest.New(t, scanningtest.ModeHang)
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	enableMalwareScan(cfg, srv)
	t.Cleanup(resetAssemblyRootCtx) // don't leak a cancelled root ctx into later tests in this package

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	uploadID := "550e8400-e29b-41d4-a716-446655440083"
	content := bytes.Repeat([]byte("a"), 512)
	partialUpload := &models.PartialUpload{
		UploadID: uploadID, Filename: "test.bin", TotalSize: int64(len(content)), ChunkSize: int64(len(content)),
		TotalChunks: 1, ExpiresInHours: 24, CreatedAt: time.Now(), LastActivity: time.Now(),
	}
	if err := repos.PartialUploads.Create(ctx, partialUpload); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := utils.SaveChunk(cfg.UploadDir, uploadID, 0, content); err != nil {
		t.Fatalf("SaveChunk: %v", err)
	}

	lease := repository.AssemblyLease{Owner: "shutdown-test-owner", TTL: time.Minute}
	locked, err := repos.PartialUploads.TryLockForProcessing(ctx, uploadID, lease)
	if err != nil || !locked {
		t.Fatalf("TryLockForProcessing: locked=%v err=%v", locked, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runAssembly(repos, cfg, partialUpload, lease)
	}()

	// Let the scan actually start streaming to clamd before cutting it off.
	time.Sleep(300 * time.Millisecond)
	CancelAssemblies()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runAssembly did not return after CancelAssemblies")
	}

	result, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetByUploadID: %v", err)
	}
	if result.Status != "processing" {
		t.Fatalf("status = %q, want processing (left for recovery)", result.Status)
	}
	if result.ErrorCode != nil {
		t.Errorf("error_code = %v, want nil (must not be misrecorded as SCAN_UNAVAILABLE)", *result.ErrorCode)
	}
	// The lease must be immediately takeover-eligible (yielded), not left to
	// ride out the rest of its TTL — verified functionally (rather than by
	// re-parsing the stored timestamp) by confirming TakeOverExpiredLease
	// actually succeeds right now.
	tookOver, err := repos.PartialUploads.TakeOverExpiredLease(ctx, uploadID, repository.AssemblyLease{Owner: "recovery-owner", TTL: time.Minute}, 5)
	if err != nil {
		t.Fatalf("TakeOverExpiredLease: %v", err)
	}
	if !tookOver {
		t.Error("expected the yielded lease to be immediately takeover-eligible")
	}
	if result.AssemblyAttempts != 1 {
		t.Errorf("assembly_attempts = %d, want 1 (unchanged — no attempt burned on a shutdown abort)", result.AssemblyAttempts)
	}
}

// publishAckDroppedWrapper wraps a real PartialUploadRepository and, for
// PublishAssembly only, lets the real call go through (so the commit
// genuinely happens) but then returns a synthetic error — simulating a
// connection drop between COMMIT and the client receiving the
// acknowledgement.
type publishAckDroppedWrapper struct {
	repository.PartialUploadRepository
}

func (w *publishAckDroppedWrapper) PublishAssembly(ctx context.Context, uploadID, owner string, file *models.File) error {
	if err := w.PartialUploadRepository.PublishAssembly(ctx, uploadID, owner, file); err != nil {
		return err
	}
	return errors.New("simulated: connection dropped after commit, before ack")
}

// TestAssembleUploadAsync_AmbiguousCommitError_KeepsPublishedFile is a
// bug-hunter regression test (ADR-016 M3): if PublishAssembly's commit
// actually succeeds on the server but the acknowledgement is lost (e.g. the
// connection drops right after COMMIT), the worker must not treat that as a
// failure — the row is genuinely "completed" with a valid, already-issued
// claim code. The old code unconditionally deleted finalPath and called
// w.fail (which harmlessly no-ops via ErrLeaseLost since the row is no
// longer "processing"), silently destroying the only copy of the file while
// leaving a live claim code pointing at nothing.
func TestAssembleUploadAsync_AmbiguousCommitError_KeepsPublishedFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	// Wrap only PartialUploads; Files stays real so GetByClaimCode below
	// sees the row PublishAssembly's transaction actually committed.
	repos.PartialUploads = &publishAckDroppedWrapper{PartialUploadRepository: repos.PartialUploads}

	ctx := context.Background()
	uploadID := "550e8400-e29b-41d4-a716-446655440084"
	content := []byte("hello world, this is the published content")
	partialUpload := &models.PartialUpload{
		UploadID: uploadID, Filename: "test.txt", TotalSize: int64(len(content)), ChunkSize: int64(len(content)),
		TotalChunks: 1, ExpiresInHours: 24, CreatedAt: time.Now(), LastActivity: time.Now(),
	}
	if err := repos.PartialUploads.Create(ctx, partialUpload); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := utils.SaveChunk(cfg.UploadDir, uploadID, 0, content); err != nil {
		t.Fatalf("SaveChunk: %v", err)
	}

	assembleUploadSync(t, repos, cfg, partialUpload)

	result, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if err != nil {
		t.Fatalf("GetByUploadID: %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("status = %q, want completed (the commit genuinely succeeded)", result.Status)
	}
	if result.ClaimCode == nil || *result.ClaimCode == "" {
		t.Fatal("expected a claim code to be set")
	}

	file, err := repos.Files.GetByClaimCode(ctx, *result.ClaimCode)
	if err != nil || file == nil {
		t.Fatalf("GetByClaimCode: file=%v err=%v", file, err)
	}

	// The published file's bytes must still be on disk — not deleted by the
	// ambiguous-error handling.
	storedPath := filepath.Join(cfg.UploadDir, file.StoredFilename)
	if _, statErr := os.Stat(storedPath); statErr != nil {
		t.Errorf("expected published file to still exist at %s: %v", storedPath, statErr)
	}

	// Chunks must still have been cleaned up, same as an unambiguous success.
	chunkDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	if _, statErr := os.Stat(chunkDir); statErr == nil {
		t.Error("expected chunks directory to be cleaned up after a (falsely-reported-failed) successful publish")
	}
}

// publishAckDroppedAndRereadFailsWrapper extends publishAckDroppedWrapper:
// every GetByUploadID call also fails, simulating the worst case for the
// follow-up bug-hunter finding on M3 — the ambiguous publish error AND the
// re-read used to resolve it both fail, most plausibly because the DB is
// still unreachable. In that case the worker cannot tell whether the
// commit went through and must not guess either way.
type publishAckDroppedAndRereadFailsWrapper struct {
	*publishAckDroppedWrapper
}

func (w *publishAckDroppedAndRereadFailsWrapper) GetByUploadID(ctx context.Context, uploadID string) (*models.PartialUpload, error) {
	return nil, errors.New("simulated: DB still unreachable")
}

// TestAssembleUploadAsync_AmbiguousCommitError_RereadAlsoFails_LeavesFinalPathUntouched
// is a bug-hunter follow-up regression test on M3: when the ambiguous-commit
// re-read (added to resolve M3) itself fails after retries, the worker must
// not fall back to deleting finalPath and recording ASSEMBLY_FAILED — the
// commit may well have actually succeeded, and destroying the file would
// leave a "completed" row with a valid claim code but no bytes behind it.
// The correct outcome is UNKNOWN: leave finalPath on disk, don't touch the
// row, and let the lease eventually expire for recovery to re-evaluate.
func TestAssembleUploadAsync_AmbiguousCommitError_RereadAlsoFails_LeavesFinalPathUntouched(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	base := &publishAckDroppedWrapper{PartialUploadRepository: repos.PartialUploads}
	repos.PartialUploads = &publishAckDroppedAndRereadFailsWrapper{publishAckDroppedWrapper: base}

	ctx := context.Background()
	uploadID := "550e8400-e29b-41d4-a716-446655440085"
	content := []byte("hello world, this is the published content, take two")
	partialUpload := &models.PartialUpload{
		UploadID: uploadID, Filename: "test.txt", TotalSize: int64(len(content)), ChunkSize: int64(len(content)),
		TotalChunks: 1, ExpiresInHours: 24, CreatedAt: time.Now(), LastActivity: time.Now(),
	}
	if err := repos.PartialUploads.Create(ctx, partialUpload); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := utils.SaveChunk(cfg.UploadDir, uploadID, 0, content); err != nil {
		t.Fatalf("SaveChunk: %v", err)
	}

	assembleUploadSync(t, repos, cfg, partialUpload)

	// The underlying PublishAssembly call actually committed (same as the
	// ack-dropped case above), so the row really is "completed" with a
	// valid claim code — this test isn't about that transition, only about
	// what the worker does with finalPath and the row when it CAN'T
	// discover that fact. Fetch directly through the real repo (bypassing
	// the always-failing wrapper) to inspect ground truth.
	realResult, realErr := base.PartialUploadRepository.GetByUploadID(ctx, uploadID)
	if realErr != nil {
		t.Fatalf("GetByUploadID (real): %v", realErr)
	}
	if realResult.Status != "completed" {
		t.Fatalf("status = %q, want completed (the underlying commit still actually succeeded)", realResult.Status)
	}
	if realResult.ClaimCode == nil || *realResult.ClaimCode == "" {
		t.Fatal("expected a claim code to be set")
	}

	file, fileErr := repos.Files.GetByClaimCode(ctx, *realResult.ClaimCode)
	if fileErr != nil || file == nil {
		t.Fatalf("GetByClaimCode: file=%v err=%v", file, fileErr)
	}

	// The core assertion: finalPath must still exist. A worker that gave up
	// and deleted it after a failed re-read would destroy the only copy of
	// an already-published file.
	storedPath := filepath.Join(cfg.UploadDir, file.StoredFilename)
	if _, statErr := os.Stat(storedPath); statErr != nil {
		t.Errorf("expected finalPath to still exist at %s after an unresolvable ambiguous commit: %v", storedPath, statErr)
	}
}
