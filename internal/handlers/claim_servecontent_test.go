package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

const testClaimEncKey = "a5430a07e3a717ecb23f8909d2fad498ccec6b3ca4d911e64bb133e29d25ec4d"

func TestClaimHandler_HEAD_HeadersMatchGET_NoConsumption(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	content := bytes.Repeat([]byte("H"), 2048)
	storedFilename := "sc-head-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	maxDownloads := 1
	file := &models.File{
		ClaimCode:        "schead1",
		OriginalFilename: "head.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		MaxDownloads:     &maxDownloads,
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	// HEAD must not consume the single available download.
	headReq := httptest.NewRequest(http.MethodHead, "/api/claim/schead1", nil)
	headRR := httptest.NewRecorder()
	handler.ServeHTTP(headRR, headReq)

	testutil.AssertStatusCode(t, headRR, http.StatusOK)
	if headRR.Body.Len() != 0 {
		t.Errorf("HEAD response body length = %d, want 0", headRR.Body.Len())
	}
	if got := headRR.Header().Get("Content-Length"); got != "2048" {
		t.Errorf("HEAD Content-Length = %q, want 2048", got)
	}
	if got := headRR.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Errorf("HEAD Accept-Ranges = %q, want bytes", got)
	}
	if got := headRR.Header().Get("ETag"); got == "" {
		t.Error("HEAD response missing ETag")
	}
	if got := headRR.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("HEAD Cache-Control = %q, want %q", got, "private, no-store")
	}
	if got := headRR.Header().Get("X-Download-Session"); got != "" {
		t.Errorf("HEAD must not mint a download session token, got %q", got)
	}

	afterHead, err := repos.Files.GetByClaimCode(ctx, "schead1")
	if err != nil {
		t.Fatalf("get file: %v", err)
	}
	if afterHead.DownloadCount != 0 {
		t.Errorf("after HEAD: download_count = %d, want 0", afterHead.DownloadCount)
	}

	// A subsequent GET must still succeed and consume the one download.
	getReq := httptest.NewRequest(http.MethodGet, "/api/claim/schead1", nil)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	testutil.AssertStatusCode(t, getRR, http.StatusOK)
	if !bytes.Equal(getRR.Body.Bytes(), content) {
		t.Error("GET body mismatch")
	}

	afterGet, err := repos.Files.GetByClaimCode(ctx, "schead1")
	if err != nil {
		t.Fatalf("get file: %v", err)
	}
	if afterGet.DownloadCount != 1 {
		t.Errorf("after GET: download_count = %d, want 1", afterGet.DownloadCount)
	}
}

func TestClaimHandler_HEAD_MethodAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := ClaimHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodHead, "/api/claim/nonexistent", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusMethodNotAllowed {
		t.Errorf("HEAD should be an accepted method, got 405")
	}
	if got := rr.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("Cache-Control = %q, want %q even on a 404", got, "private, no-store")
	}
}

func TestClaimHandler_HEAD_PasswordGated(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	content := []byte("secret content")
	storedFilename := "sc-head-pw-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	hash, err := utils.HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scheadpw",
		OriginalFilename: "pw.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		PasswordHash:     hash,
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	// HEAD without password: same 401 gate as GET.
	req := httptest.NewRequest(http.MethodHead, "/api/claim/scheadpw", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	testutil.AssertStatusCode(t, rr, http.StatusUnauthorized)

	// HEAD with the correct password succeeds.
	req2 := httptest.NewRequest(http.MethodHead, "/api/claim/scheadpw", nil)
	req2.Header.Set("X-File-Password", "correct-horse")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	testutil.AssertStatusCode(t, rr2, http.StatusOK)
}

func TestClaimHandler_ConditionalGet_NotModified_DoesNotConsume(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	content := bytes.Repeat([]byte("Z"), 512)
	storedFilename := "sc-cond-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	maxDownloads := 1
	file := &models.File{
		ClaimCode:        "sccond1",
		OriginalFilename: "cond.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		MaxDownloads:     &maxDownloads,
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}
	created, err := repos.Files.GetByClaimCode(ctx, "sccond1")
	if err != nil || created == nil {
		t.Fatalf("get file: %v", err)
	}
	etag := utils.ComputeClaimETag(created.StoredFilename, created.FileSize, created.CreatedAt)

	req := httptest.NewRequest(http.MethodGet, "/api/claim/sccond1", nil)
	req.Header.Set("If-None-Match", etag)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusNotModified)
	if rr.Body.Len() != 0 {
		t.Errorf("304 response body length = %d, want 0", rr.Body.Len())
	}

	after, err := repos.Files.GetByClaimCode(ctx, "sccond1")
	if err != nil {
		t.Fatalf("get file: %v", err)
	}
	if after.DownloadCount != 0 {
		t.Errorf("after 304: download_count = %d, want 0 (must not consume a download)", after.DownloadCount)
	}

	// The slot must still be available for a real GET afterwards.
	getReq := httptest.NewRequest(http.MethodGet, "/api/claim/sccond1", nil)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	testutil.AssertStatusCode(t, getRR, http.StatusOK)
}

func TestClaimHandler_ETag_PresentAndStrong(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	handler := ClaimHandler(repos, cfg)
	ctx := context.Background()

	content := []byte("etag test content")
	storedFilename := "sc-etag-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scetag1",
		OriginalFilename: "etag.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/claim/scetag1", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	testutil.AssertStatusCode(t, rr, http.StatusOK)

	etag := rr.Header().Get("ETag")
	if len(etag) != 34 || etag[0] != '"' || etag[33] != '"' { // "+32 hex+"
		t.Errorf("ETag = %q, want a quoted 32-hex-char strong validator", etag)
	}
	if lastMod := rr.Header().Get("Last-Modified"); lastMod == "" {
		t.Error("missing Last-Modified header")
	}
}

func TestClaimHandler_SFSE2_WithoutKey_FailsClosed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("S"), 4096)
	srcPath := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	storedFilename := "sc-sfse2-nokey-uuid.bin"
	dstPath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := utils.EncryptFileStreamingV2(srcPath, dstPath, testClaimEncKey, encFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}

	sum := sha256.Sum256(plaintext)
	file := &models.File{
		ClaimCode:        "scsfse2nokey",
		OriginalFilename: "encrypted.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		EncFileID:        encFileID,
		SHA256Hash:       hex.EncodeToString(sum[:]),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	// cfg has no EncryptionKey (testutil default): the stored SFSE2 file's
	// size cannot match dbFileSize, and no key means ClassifyStoredFile
	// must fail closed rather than trying to stream ciphertext as if it
	// were plaintext.
	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scsfse2nokey", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusInternalServerError)
	if bytes.Contains(rr.Body.Bytes(), plaintext[:16]) {
		t.Error("response must never leak plaintext-shaped bytes on a fail-closed 500")
	}
}

func TestClaimHandler_SFSE2_Truncated_FailsBeforeHeaders(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("T"), 4096)
	srcPath := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	storedFilename := "sc-sfse2-trunc-uuid.bin"
	dstPath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := utils.EncryptFileStreamingV2(srcPath, dstPath, testClaimEncKey, encFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}

	// Truncate the ciphertext by a few bytes — this must be caught by
	// OpenSFSEReader's exact-size check at open time, before any header is
	// written, not surfaced as a mid-stream error after a 200/206 started.
	fi, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Truncate(dstPath, fi.Size()-4); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	sum := sha256.Sum256(plaintext)
	file := &models.File{
		ClaimCode:        "scsfse2trunc",
		OriginalFilename: "encrypted.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		EncFileID:        encFileID,
		SHA256Hash:       hex.EncodeToString(sum[:]),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scsfse2trunc", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusInternalServerError)
}

func TestClaimHandler_SFSE2_RoundTrip(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("R"), 8192)
	srcPath := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	storedFilename := "sc-sfse2-round-uuid.bin"
	dstPath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := utils.EncryptFileStreamingV2(srcPath, dstPath, testClaimEncKey, encFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}

	sum := sha256.Sum256(plaintext)
	file := &models.File{
		ClaimCode:        "scsfse2round",
		OriginalFilename: "encrypted.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		EncFileID:        encFileID,
		SHA256Hash:       hex.EncodeToString(sum[:]),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)

	// Full-file GET.
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scsfse2round", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	testutil.AssertStatusCode(t, rr, http.StatusOK)
	if !bytes.Equal(rr.Body.Bytes(), plaintext) {
		t.Error("full SFSE2 download mismatch")
	}

	// Ranged GET.
	rangeReq := httptest.NewRequest(http.MethodGet, "/api/claim/scsfse2round", nil)
	rangeReq.Header.Set("Range", "bytes=100-199")
	rangeRR := httptest.NewRecorder()
	handler.ServeHTTP(rangeRR, rangeReq)
	testutil.AssertStatusCode(t, rangeRR, http.StatusPartialContent)
	if !bytes.Equal(rangeRR.Body.Bytes(), plaintext[100:200]) {
		t.Error("ranged SFSE2 download mismatch")
	}
}

func TestClaimHandler_PlaintextWithKeyConfigured_ServedAsPlaintext(t *testing.T) {
	// T9: a plaintext file (e.g. uploaded via import-file without
	// --enckey, or before ENCRYPTION_KEY was ever set) must still be
	// served correctly once a key IS configured — classification must be
	// size-based, not "is a key configured".
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	content := bytes.Repeat([]byte("P"), 1024)
	storedFilename := "sc-plain-withkey-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "scplainkey",
		OriginalFilename: "plain.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scplainkey", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)
	if !bytes.Equal(rr.Body.Bytes(), content) {
		t.Error("plaintext-with-key-configured download mismatch")
	}
}

func TestClaimHandler_LegacyEncrypted_OverCap_FailsClosed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	cfg.LegacyDecryptMaxBytes = 64 // tiny cap so any nonzero content trips it
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("L"), 4096)
	encrypted, err := utils.EncryptFile(plaintext, testClaimEncKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	storedFilename := "sc-legacy-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), encrypted, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "sclegacycap",
		OriginalFilename: "legacy.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/sclegacycap", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusInternalServerError)
}

func TestClaimHandler_LegacyEncrypted_UnderCap_Served(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("K"), 4096)
	encrypted, err := utils.EncryptFile(plaintext, testClaimEncKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	storedFilename := "sc-legacy-ok-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), encrypted, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "sclegacyok",
		OriginalFilename: "legacy.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/sclegacyok", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusOK)
	if !bytes.Equal(rr.Body.Bytes(), plaintext) {
		t.Error("legacy download mismatch")
	}
}

func TestClaimHandler_DecryptAdmission_Exhausted_Returns503(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("A"), 4096)
	srcPath := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	storedFilename := "sc-admission-uuid.bin"
	dstPath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := utils.EncryptFileStreamingV2(srcPath, dstPath, testClaimEncKey, encFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}

	sum := sha256.Sum256(plaintext)
	file := &models.File{
		ClaimCode:        "scadmission",
		OriginalFilename: "encrypted.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		EncFileID:        encFileID,
		SHA256Hash:       hex.EncodeToString(sum[:]),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	// Install a budget of 1 byte — any real chunk-buffer weight exceeds it,
	// but Acquire clamps an over-large weight to the full capacity rather
	// than rejecting outright, so pre-occupy that one byte from a
	// concurrent "holder" acquire to actually force exhaustion.
	original := decryptAdmission
	admission := utils.NewDecryptAdmission(1)
	decryptAdmission = admission
	t.Cleanup(func() { decryptAdmission = original })

	holderCtx, holderCancel := context.WithCancel(context.Background())
	t.Cleanup(holderCancel)
	if _, err := admission.Acquire(holderCtx, 1); err != nil {
		t.Fatalf("holder acquire: %v", err)
	}
	t.Cleanup(func() { admission.Release(1) })

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/scadmission", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusServiceUnavailable)
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Error("503 response missing Retry-After")
	}
}

// TestClaimHandler_HEAD_DownloadLimitReached_Returns410 is a code-review
// regression test: the first cut's HEAD short-circuit sat before
// ClaimHandler's download-limit logic entirely, so a HEAD against an
// already-exhausted capped file returned 200 with real headers while a GET
// to the same URL correctly returned 410 — an inconsistency that directly
// contradicts HEAD's "never promise what a GET wouldn't deliver" contract.
func TestClaimHandler_HEAD_DownloadLimitReached_Returns410(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	content := bytes.Repeat([]byte("D"), 512)
	storedFilename := "sc-head-limit-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	maxDownloads := 1
	file := &models.File{
		ClaimCode:        "scheadlimit",
		OriginalFilename: "limit.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		MaxDownloads:     &maxDownloads,
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)

	// Consume the single available download via GET.
	getReq := httptest.NewRequest(http.MethodGet, "/api/claim/scheadlimit", nil)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	testutil.AssertStatusCode(t, getRR, http.StatusOK)

	after, err := repos.Files.GetByClaimCode(ctx, "scheadlimit")
	if err != nil {
		t.Fatalf("get file: %v", err)
	}
	if after.DownloadCount != 1 {
		t.Fatalf("precondition failed: download_count = %d, want 1", after.DownloadCount)
	}

	// HEAD on the now-exhausted file must report the same limit a GET would
	// (a normal sendErrorResponse JSON error body, same as GET's 410 —
	// HEAD's "no body" property only applies to the actual file-serving
	// path through http.ServeContent, not to error responses written
	// directly by this handler).
	headReq := httptest.NewRequest(http.MethodHead, "/api/claim/scheadlimit", nil)
	headRR := httptest.NewRecorder()
	handler.ServeHTTP(headRR, headReq)
	testutil.AssertStatusCode(t, headRR, http.StatusGone)
}

// TestClaimHandler_HEAD_LegacyFile_SkipsDecrypt is a code-review regression
// test: the first cut's HEAD short-circuit called the same
// serveFileWithRangeSupport path a GET uses with no method-specific
// handling inside it, so a HEAD against a legacy-encrypted file still did
// the full io.ReadAll+DecryptFile (and tried to acquire decrypt-admission
// budget for it) just to report a size already known from the database.
// This proves HEAD skips all of that: with the decrypt-admission budget
// fully exhausted by another holder (so any code path that tried to
// acquire from it would block for decryptAdmissionWaitTimeout and then
// 503), HEAD still succeeds immediately.
func TestClaimHandler_HEAD_LegacyFile_SkipsDecrypt(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("Q"), 4096)
	encrypted, err := utils.EncryptFile(plaintext, testClaimEncKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	storedFilename := "sc-legacy-head-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), encrypted, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file := &models.File{
		ClaimCode:        "sclegacyhead",
		OriginalFilename: "legacy.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	// Fully exhaust the decrypt admission budget. Any code path that tries
	// to acquire from it — even a single byte, since Acquire clamps an
	// oversized weight to capacity rather than rejecting outright — would
	// block until decryptAdmissionWaitTimeout (3s) and then 503.
	original := decryptAdmission
	admission := utils.NewDecryptAdmission(1)
	decryptAdmission = admission
	t.Cleanup(func() { decryptAdmission = original })
	holderCtx, holderCancel := context.WithCancel(context.Background())
	t.Cleanup(holderCancel)
	if _, err := admission.Acquire(holderCtx, 1); err != nil {
		t.Fatalf("holder acquire: %v", err)
	}
	t.Cleanup(func() { admission.Release(1) })

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodHead, "/api/claim/sclegacyhead", nil)
	rr := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	testutil.AssertStatusCode(t, rr, http.StatusOK)
	if rr.Body.Len() != 0 {
		t.Errorf("HEAD body length = %d, want 0", rr.Body.Len())
	}
	if got := rr.Header().Get("Content-Length"); got != strconv.Itoa(len(plaintext)) {
		t.Errorf("Content-Length = %q, want %d", got, len(plaintext))
	}
	// A generous bound well under decryptAdmissionWaitTimeout (3s): if HEAD
	// incorrectly tried to acquire admission budget, it would block for the
	// full timeout before failing with 503.
	if elapsed > time.Second {
		t.Errorf("HEAD took %v against an exhausted admission budget — it must not attempt to acquire any (i.e. must not decrypt)", elapsed)
	}
}

// TestClaimHandler_EncryptedRangeIPTracker_ReturnsTooManyRequests exercises
// the ADR-017 per-IP concurrency backstop for encrypted claim downloads
// (encryptedRangeIPTracker, sized from MAX_ENCRYPTED_DOWNLOADS_PER_IP):
// once a client IP has encryptedRangeIPTracker.MaxPerIP() encrypted
// downloads already in flight, a further one is rejected with 429 rather
// than being served (or queued against the shared memory budget).
func TestClaimHandler_EncryptedRangeIPTracker_ReturnsTooManyRequests(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.EncryptionKey = testClaimEncKey
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	plaintext := bytes.Repeat([]byte("I"), 4096)
	srcPath := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	storedFilename := "sc-iptracker-uuid.bin"
	dstPath := filepath.Join(cfg.UploadDir, storedFilename)
	if err := utils.EncryptFileStreamingV2(srcPath, dstPath, testClaimEncKey, encFileID); err != nil {
		t.Fatalf("EncryptFileStreamingV2: %v", err)
	}

	sum := sha256.Sum256(plaintext)
	file := &models.File{
		ClaimCode:        "sciptracker",
		OriginalFilename: "encrypted.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		EncFileID:        encFileID,
		SHA256Hash:       hex.EncodeToString(sum[:]),
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	const clientIP = "203.0.113.77"

	// Saturate the per-IP tracker directly (white-box: same package).
	for i := 0; i < encryptedRangeIPTracker.MaxPerIP(); i++ {
		if !encryptedRangeIPTracker.TryAcquire(encryptedRangeIPTrackerKey, clientIP) {
			t.Fatalf("failed to saturate tracker at slot %d", i)
		}
	}
	t.Cleanup(func() {
		for i := 0; i < encryptedRangeIPTracker.MaxPerIP(); i++ {
			encryptedRangeIPTracker.Release(encryptedRangeIPTrackerKey, clientIP)
		}
	})

	handler := ClaimHandler(repos, cfg)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/sciptracker", nil)
	req.RemoteAddr = clientIP + ":54321"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	testutil.AssertStatusCode(t, rr, http.StatusTooManyRequests)
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Error("429 response missing Retry-After")
	}

	// A different client IP must be unaffected.
	req2 := httptest.NewRequest(http.MethodGet, "/api/claim/sciptracker", nil)
	req2.RemoteAddr = "198.51.100.9:1111"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	testutil.AssertStatusCode(t, rr2, http.StatusOK)
}

// TestSession_UnsatisfiableRange_ReleasesReservation is a code-review
// regression test for the capped-download path: a Range request that
// resolves to RangeUnsatisfiable must reply 416 without ever committing
// the download, and the reservation slot it took (before the outcome was
// known) must be fully released afterward — not just "not counted," but
// the in-flight ceiling itself must be back to where a fresh reservation
// can succeed.
func TestSession_UnsatisfiableRange_ReleasesReservation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()

	content := bytes.Repeat([]byte("U"), 1024)
	storedFilename := "sc-unsat-uuid.bin"
	if err := os.WriteFile(filepath.Join(cfg.UploadDir, storedFilename), content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	maxDownloads := 1
	file := &models.File{
		ClaimCode:        "scunsat1",
		OriginalFilename: "unsat.bin",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(content)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		MaxDownloads:     &maxDownloads,
	}
	if err := repos.Files.Create(ctx, file); err != nil {
		t.Fatalf("create file: %v", err)
	}

	handler := ClaimHandler(repos, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/claim/scunsat1", nil)
	req.Header.Set("Range", "bytes=99999-999999") // start beyond file size
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	testutil.AssertStatusCode(t, rr, http.StatusRequestedRangeNotSatisfiable)

	got, err := repos.Files.GetByClaimCode(ctx, "scunsat1")
	if err != nil {
		t.Fatalf("get file: %v", err)
	}
	if got.DownloadCount != 0 {
		t.Errorf("after 416: download_count = %d, want 0", got.DownloadCount)
	}
	if got.UncountedBytes != 0 {
		t.Errorf("after 416: uncounted_bytes = %d, want 0 (nothing was ever actually sent)", got.UncountedBytes)
	}

	// The reservation ceiling itself must be back: a fresh ReserveDownload
	// against this max_downloads=1 file must succeed (it would be rejected
	// if the earlier request's in-flight slot had leaked).
	token, _, err := repos.Files.ReserveDownload(ctx, got.ID, got.ClaimCode)
	if err != nil {
		t.Fatalf("ReserveDownload after unsatisfiable range: %v", err)
	}
	if token == "" {
		t.Fatal("reservation slot leaked: fresh ReserveDownload was rejected after a 416")
	}
	if err := repos.Files.CancelDownload(ctx, got.ID, token); err != nil {
		t.Errorf("cleanup CancelDownload: %v", err)
	}

	// And a real, satisfiable download must still succeed afterward.
	getReq := httptest.NewRequest(http.MethodGet, "/api/claim/scunsat1", nil)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	testutil.AssertStatusCode(t, getRR, http.StatusOK)
}
