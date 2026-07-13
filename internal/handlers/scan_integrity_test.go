package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/scanning"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// fakeScanner is a test double for scanning.Scanner. It records the content of
// the file it was asked to scan (so tests can assert PLAINTEXT was scanned, not
// ciphertext) and returns a caller-configured result.
type fakeScanner struct {
	result   *scanning.ScanResult
	err      error
	scanned  []byte // bytes read from the path handed to ScanFile
	scanPath string
}

func (f *fakeScanner) ScanFile(filePath string) (*scanning.ScanResult, error) {
	f.scanPath = filePath
	if data, err := os.ReadFile(filePath); err == nil {
		f.scanned = data
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

// withFakeScanner swaps newConfiguredScanner for the duration of a test and
// restores it afterwards. The package-level seam lets us exercise the full
// upload path without a live clamd.
func withFakeScanner(t *testing.T, fs *fakeScanner) {
	t.Helper()
	orig := newConfiguredScanner
	newConfiguredScanner = func(*config.Config) scanning.Scanner { return fs }
	t.Cleanup(func() { newConfiguredScanner = orig })
}

func TestScanPlaintextFile_Classification(t *testing.T) {
	tests := []struct {
		name       string
		result     *scanning.ScanResult
		err        error
		wantStatus string
	}{
		{
			name:       "clean verdict",
			result:     &scanning.ScanResult{Clean: true},
			wantStatus: scanning.ScanStatusClean,
		},
		{
			name:       "infected verdict",
			result:     &scanning.ScanResult{Infected: true, VirusName: "Eicar-Test-Signature"},
			wantStatus: scanning.ScanStatusInfected,
		},
		{
			name:       "scan error fails closed",
			err:        os.ErrDeadlineExceeded,
			wantStatus: scanning.ScanStatusError,
		},
		{
			name:       "inconclusive reply fails closed",
			result:     &scanning.ScanResult{Unknown: true, RawResponse: "INSTREAM size limit exceeded. ERROR"},
			wantStatus: scanning.ScanStatusError,
		},
		{
			name:       "empty result fails closed",
			result:     &scanning.ScanResult{},
			wantStatus: scanning.ScanStatusError,
		},
	}

	// A real file must exist for the err/nil-result cases that still read it.
	tmp := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(tmp, []byte("payload"), 0644); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &fakeScanner{result: tt.result, err: tt.err}
			got := scanPlaintextFile(fs, tmp)
			if got.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", got.Status, tt.wantStatus)
			}
			if tt.wantStatus == scanning.ScanStatusInfected && got.VirusName != "Eicar-Test-Signature" {
				t.Errorf("virus name = %q, want Eicar-Test-Signature", got.VirusName)
			}
		})
	}
}

// TestUploadHandler_ScansPlaintextBeforeEncrypt is the 1a regression guard: with
// encryption on, the scanner must receive the PLAINTEXT, never the SFSE2
// ciphertext (which would never match a signature).
func TestUploadHandler_ScansPlaintextBeforeEncrypt(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Features.SetMalwareScanEnabled(true)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	fs := &fakeScanner{result: &scanning.ScanResult{Clean: true}}
	withFakeScanner(t, fs)

	handler := UploadHandler(repos, cfg)

	plaintext := []byte("clean plaintext body that clamd should see")
	body, contentType := testutil.CreateMultipartForm(t, plaintext, "clean.txt", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.UploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	// Scanner must have been handed the plaintext, not the ciphertext.
	if string(fs.scanned) != string(plaintext) {
		t.Errorf("scanner saw %q, want plaintext %q", fs.scanned, plaintext)
	}

	// Stored file on disk must be encrypted (differs from plaintext) and no
	// plaintext temp should linger.
	entries, _ := os.ReadDir(cfg.UploadDir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("plaintext/temp file lingered: %s", e.Name())
		}
	}
	ctx := context.Background()
	file, err := repos.Files.GetByClaimCode(ctx, resp.ClaimCode)
	if err != nil || file == nil {
		t.Fatalf("get file: %v", err)
	}
	if file.ScanStatus != scanning.ScanStatusClean {
		t.Errorf("scan status = %q, want clean", file.ScanStatus)
	}
	stored, err := os.ReadFile(filepath.Join(cfg.UploadDir, file.StoredFilename))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if string(stored) == string(plaintext) {
		t.Error("stored file is plaintext; expected SFSE2 ciphertext")
	}
}

// TestUploadHandler_InfectedFilePurgedAndRecorded verifies the infected path:
// the record persists with an infected status and the stored file is removed.
func TestUploadHandler_InfectedFilePurgedAndRecorded(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.Features.SetMalwareScanEnabled(true)

	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}

	fs := &fakeScanner{result: &scanning.ScanResult{Infected: true, VirusName: "Eicar-Test-Signature"}}
	withFakeScanner(t, fs)

	handler := UploadHandler(repos, cfg)

	body, contentType := testutil.CreateMultipartForm(t, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}"), "virus.txt", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusCreated)

	var resp models.UploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	ctx := context.Background()
	file, err := repos.Files.GetByClaimCode(ctx, resp.ClaimCode)
	if err != nil || file == nil {
		t.Fatalf("get file: %v", err)
	}
	if file.ScanStatus != scanning.ScanStatusInfected {
		t.Errorf("scan status = %q, want infected", file.ScanStatus)
	}
	if file.ScanResult != "Eicar-Test-Signature" {
		t.Errorf("scan result = %q, want Eicar-Test-Signature", file.ScanResult)
	}

	// handleInfectedFile removes the stored file from disk.
	if _, statErr := os.Stat(filepath.Join(cfg.UploadDir, file.StoredFilename)); !os.IsNotExist(statErr) {
		t.Errorf("infected file still on disk, want removed (err=%v)", statErr)
	}
}

// TestClaimHandler_ScanGate exercises the 1b fail-closed download gate.
func TestClaimHandler_ScanGate(t *testing.T) {
	tests := []struct {
		name       string
		scanStatus string
		wantCode   int
		wantErr    string
	}{
		{"pending returns 425", scanning.ScanStatusPending, http.StatusTooEarly, "SCAN_PENDING"},
		{"error returns 403", scanning.ScanStatusError, http.StatusForbidden, "SCAN_NOT_CLEAN"},
		{"clean returns 200", scanning.ScanStatusClean, http.StatusOK, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := testutil.SetupTestDB(t)
			cfg := testutil.SetupTestConfig(t)
			cfg.Features.SetMalwareScanEnabled(true)
			cfg.Features.SetMalwareScanBlockUntilClean(true)

			repos, err := sqlite.NewRepositories(cfg, db)
			if err != nil {
				t.Fatalf("failed to create repositories: %v", err)
			}
			handler := ClaimHandler(repos, cfg)
			ctx := context.Background()

			content := []byte("gate test body")
			storedFilename := "gate-" + tt.scanStatus + ".txt"
			if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
				t.Fatalf("write file: %v", err)
			}

			file := &models.File{
				ClaimCode:        "gate" + tt.scanStatus,
				OriginalFilename: "doc.txt",
				StoredFilename:   storedFilename,
				FileSize:         int64(len(content)),
				MimeType:         "text/plain",
				ExpiresAt:        time.Now().Add(24 * time.Hour),
				UploaderIP:       "127.0.0.1",
				ScanStatus:       tt.scanStatus,
			}
			if err := repos.Files.Create(ctx, file); err != nil {
				t.Fatalf("create record: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/api/claim/"+file.ClaimCode, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			testutil.AssertStatusCode(t, rr, tt.wantCode)

			if tt.scanStatus == scanning.ScanStatusPending {
				if rr.Header().Get("Retry-After") == "" {
					t.Error("pending response missing Retry-After header")
				}
			}

			if tt.wantErr != "" {
				var errResp models.ErrorResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
					t.Fatalf("parse error response: %v", err)
				}
				if errResp.Code != tt.wantErr {
					t.Errorf("error code = %q, want %q", errResp.Code, tt.wantErr)
				}
			}
		})
	}
}
