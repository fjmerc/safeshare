package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	_ "github.com/mattn/go-sqlite3"
)

// setupPartialUploadTestDB creates an in-memory SQLite database with partial_uploads and files tables.
func setupPartialUploadTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Create partial_uploads table
	_, err = db.Exec(`
		CREATE TABLE partial_uploads (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			upload_id TEXT UNIQUE NOT NULL,
			user_id INTEGER,
			filename TEXT NOT NULL,
			total_size INTEGER NOT NULL,
			chunk_size INTEGER NOT NULL,
			total_chunks INTEGER NOT NULL,
			chunks_received INTEGER DEFAULT 0,
			received_bytes INTEGER DEFAULT 0,
			expires_in_hours INTEGER DEFAULT 24,
			max_downloads INTEGER DEFAULT 0,
			password_hash TEXT DEFAULT '',
			created_at TEXT NOT NULL,
			last_activity TEXT NOT NULL,
			completed INTEGER DEFAULT 0,
			claim_code TEXT,
			status TEXT DEFAULT 'uploading',
			error_message TEXT,
			assembly_started_at TEXT,
			assembly_completed_at TEXT,
			client_encrypted INTEGER NOT NULL DEFAULT 0,
			error_code TEXT,
			processing_owner TEXT,
			lease_expires_at TEXT,
			assembly_attempts INTEGER NOT NULL DEFAULT 0,
			error_retryable INTEGER NOT NULL DEFAULT 0,
			uploader_ip TEXT
		)
	`)
	if err != nil {
		t.Fatalf("failed to create partial_uploads table: %v", err)
	}

	// Create files table (needed for quota check, and for PublishAssembly/
	// FailAssembly's in-transaction file insert)
	_, err = db.Exec(`
		CREATE TABLE files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			claim_code TEXT UNIQUE NOT NULL,
			original_filename TEXT NOT NULL,
			stored_filename TEXT NOT NULL,
			file_size INTEGER NOT NULL,
			mime_type TEXT,
			expires_at TEXT NOT NULL,
			max_downloads INTEGER DEFAULT 0,
			download_count INTEGER DEFAULT 0,
			password_hash TEXT,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP,
			uploader_ip TEXT,
			user_id INTEGER,
			sha256_hash TEXT,
			client_encrypted INTEGER NOT NULL DEFAULT 0,
			enc_file_id BLOB,
			scan_status TEXT,
			scan_result TEXT,
			scanned_at TEXT,
			partial_upload_id TEXT
		)
	`)
	if err != nil {
		t.Fatalf("failed to create files table: %v", err)
	}
	if _, err = db.Exec(`CREATE UNIQUE INDEX idx_files_partial_upload_id ON files(partial_upload_id) WHERE partial_upload_id IS NOT NULL`); err != nil {
		t.Fatalf("failed to create files partial_upload_id index: %v", err)
	}

	return db
}

func TestNewPartialUploadRepository(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()

	repo := NewPartialUploadRepository(db)
	if repo == nil {
		t.Fatal("expected non-nil repository")
	}
	if repo.db != db {
		t.Error("expected repository to store db reference")
	}
}

func TestPartialUploadRepository_Create(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:       "test-upload-123",
		Filename:       "test.txt",
		TotalSize:      1024,
		ChunkSize:      256,
		TotalChunks:    4,
		ChunksReceived: 0,
		ReceivedBytes:  0,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      now,
		LastActivity:   now,
	}

	err := repo.Create(ctx, upload)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify insertion
	result, err := repo.GetByUploadID(ctx, "test-upload-123")
	if err != nil {
		t.Fatalf("GetByUploadID failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Filename != "test.txt" {
		t.Errorf("expected filename 'test.txt', got %q", result.Filename)
	}
	if result.Status != "uploading" {
		t.Errorf("expected status 'uploading', got %q", result.Status)
	}
}

func TestPartialUploadRepository_Create_Validation(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Test nil upload
	err := repo.Create(ctx, nil)
	if err == nil {
		t.Error("expected error for nil upload")
	}

	// Test empty upload_id
	upload := &models.PartialUpload{
		UploadID:     "",
		Filename:     "test.txt",
		TotalSize:    1024,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	err = repo.Create(ctx, upload)
	if err == nil {
		t.Error("expected error for empty upload_id")
	}
}

func TestPartialUploadRepository_CreateWithQuotaCheck(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:       "quota-test-123",
		Filename:       "test.txt",
		TotalSize:      1024,
		ChunkSize:      256,
		TotalChunks:    4,
		ChunksReceived: 0,
		ReceivedBytes:  0,
		ExpiresInHours: 24,
		CreatedAt:      now,
		LastActivity:   now,
	}

	// Test successful creation within quota
	err := repo.CreateWithQuotaCheck(ctx, upload, 10000)
	if err != nil {
		t.Fatalf("CreateWithQuotaCheck failed: %v", err)
	}

	// Verify insertion
	result, err := repo.GetByUploadID(ctx, "quota-test-123")
	if err != nil {
		t.Fatalf("GetByUploadID failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPartialUploadRepository_CreateWithQuotaCheck_Exceeded(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:       "quota-exceed-123",
		Filename:       "large.txt",
		TotalSize:      10000,
		ChunkSize:      1000,
		TotalChunks:    10,
		ChunksReceived: 0,
		ReceivedBytes:  0,
		ExpiresInHours: 24,
		CreatedAt:      now,
		LastActivity:   now,
	}

	// Test quota exceeded
	err := repo.CreateWithQuotaCheck(ctx, upload, 5000)
	if err != repository.ErrQuotaExceeded {
		t.Errorf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestPartialUploadRepository_GetByUploadID_NotFound(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	result, err := repo.GetByUploadID(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetByUploadID failed: %v", err)
	}
	if result != nil {
		t.Error("expected nil result for nonexistent upload")
	}
}

func TestPartialUploadRepository_Exists(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:     "exists-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// Test exists
	exists, err := repo.Exists(ctx, "exists-test")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("expected upload to exist")
	}

	// Test not exists
	exists, err = repo.Exists(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("expected upload to not exist")
	}
}

func TestPartialUploadRepository_UpdateActivity(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now().Add(-1 * time.Hour) // 1 hour ago
	upload := &models.PartialUpload{
		UploadID:     "activity-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// Update activity
	err := repo.UpdateActivity(ctx, "activity-test")
	if err != nil {
		t.Fatalf("UpdateActivity failed: %v", err)
	}

	// Verify activity was updated
	result, _ := repo.GetByUploadID(ctx, "activity-test")
	if result.LastActivity.Before(now.Add(30 * time.Minute)) {
		t.Error("expected last_activity to be updated to recent time")
	}
}

func TestPartialUploadRepository_IncrementChunksReceived(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:       "increment-test",
		Filename:       "test.txt",
		TotalSize:      1024,
		ChunkSize:      256,
		TotalChunks:    4,
		ChunksReceived: 0,
		ReceivedBytes:  0,
		CreatedAt:      now,
		LastActivity:   now,
	}
	_ = repo.Create(ctx, upload)

	// Increment chunks
	err := repo.IncrementChunksReceived(ctx, "increment-test", 256)
	if err != nil {
		t.Fatalf("IncrementChunksReceived failed: %v", err)
	}

	// Verify increment
	result, _ := repo.GetByUploadID(ctx, "increment-test")
	if result.ChunksReceived != 1 {
		t.Errorf("expected ChunksReceived=1, got %d", result.ChunksReceived)
	}
	if result.ReceivedBytes != 256 {
		t.Errorf("expected ReceivedBytes=256, got %d", result.ReceivedBytes)
	}
}

func TestPartialUploadRepository_IncrementChunksReceived_Validation(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Test empty upload_id
	err := repo.IncrementChunksReceived(ctx, "", 256)
	if err == nil {
		t.Error("expected error for empty upload_id")
	}

	// Test negative chunk bytes
	err = repo.IncrementChunksReceived(ctx, "test", -100)
	if err == nil {
		t.Error("expected error for negative chunk bytes")
	}
}

func TestPartialUploadRepository_Delete(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:     "delete-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// Delete
	err := repo.Delete(ctx, "delete-test")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deletion
	result, _ := repo.GetByUploadID(ctx, "delete-test")
	if result != nil {
		t.Error("expected nil result after deletion")
	}
}

func TestPartialUploadRepository_GetTotalUsage(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create uploads with received bytes
	now := time.Now()
	upload1 := &models.PartialUpload{
		UploadID:      "usage-1",
		Filename:      "test1.txt",
		TotalSize:     1024,
		ChunkSize:     256,
		TotalChunks:   4,
		ReceivedBytes: 512,
		CreatedAt:     now,
		LastActivity:  now,
	}
	_ = repo.Create(ctx, upload1)

	upload2 := &models.PartialUpload{
		UploadID:      "usage-2",
		Filename:      "test2.txt",
		TotalSize:     1024,
		ChunkSize:     256,
		TotalChunks:   4,
		ReceivedBytes: 768,
		CreatedAt:     now,
		LastActivity:  now,
	}
	_ = repo.Create(ctx, upload2)

	// Get total usage
	usage, err := repo.GetTotalUsage(ctx)
	if err != nil {
		t.Fatalf("GetTotalUsage failed: %v", err)
	}
	if usage != 1280 {
		t.Errorf("expected usage=1280, got %d", usage)
	}
}

func TestPartialUploadRepository_GetIncompleteCount(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create incomplete uploads
	now := time.Now()
	for i := 0; i < 3; i++ {
		upload := &models.PartialUpload{
			UploadID:     "count-" + string(rune('A'+i)),
			Filename:     "test.txt",
			TotalSize:    1024,
			ChunkSize:    256,
			TotalChunks:  4,
			CreatedAt:    now,
			LastActivity: now,
		}
		_ = repo.Create(ctx, upload)
	}

	count, err := repo.GetIncompleteCount(ctx)
	if err != nil {
		t.Fatalf("GetIncompleteCount failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected count=3, got %d", count)
	}
}

func TestPartialUploadRepository_GetAllUploadIDs(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create uploads
	now := time.Now()
	ids := []string{"id-A", "id-B", "id-C"}
	for _, id := range ids {
		upload := &models.PartialUpload{
			UploadID:     id,
			Filename:     "test.txt",
			TotalSize:    1024,
			ChunkSize:    256,
			TotalChunks:  4,
			CreatedAt:    now,
			LastActivity: now,
		}
		_ = repo.Create(ctx, upload)
	}

	uploadIDs, err := repo.GetAllUploadIDs(ctx)
	if err != nil {
		t.Fatalf("GetAllUploadIDs failed: %v", err)
	}
	if len(uploadIDs) != 3 {
		t.Errorf("expected 3 IDs, got %d", len(uploadIDs))
	}
	for _, id := range ids {
		if !uploadIDs[id] {
			t.Errorf("expected ID %s to be in result", id)
		}
	}
}

func TestPartialUploadRepository_UpdateStatus(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:     "status-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// Update status
	err := repo.UpdateStatus(ctx, "status-test", "processing", nil)
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	result, _ := repo.GetByUploadID(ctx, "status-test")
	if result.Status != "processing" {
		t.Errorf("expected status=processing, got %s", result.Status)
	}
}

func TestPartialUploadRepository_UpdateStatus_InvalidStatus(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	err := repo.UpdateStatus(ctx, "test", "invalid_status", nil)
	if err == nil {
		t.Error("expected error for invalid status")
	}
}

// testLease returns a short-TTL AssemblyLease with a unique owner token,
// suitable for exercising the ADR-016 CAS transitions in isolation.
func testLease(owner string) repository.AssemblyLease {
	return repository.AssemblyLease{Owner: owner, TTL: 2 * time.Minute}
}

func TestPartialUploadRepository_TryLockForProcessing(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload in uploading status
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:     "lock-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		Status:       "uploading",
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// First lock should succeed and bump assembly_attempts to 1.
	locked, err := repo.TryLockForProcessing(ctx, "lock-test", testLease("owner-1"))
	if err != nil {
		t.Fatalf("TryLockForProcessing failed: %v", err)
	}
	if !locked {
		t.Error("expected first lock to succeed")
	}
	result, _ := repo.GetByUploadID(ctx, "lock-test")
	if result.Status != "processing" {
		t.Errorf("expected status=processing, got %s", result.Status)
	}
	if result.AssemblyStartedAt == nil {
		t.Error("expected AssemblyStartedAt to be set")
	}
	if result.AssemblyAttempts != 1 {
		t.Errorf("expected AssemblyAttempts=1, got %d", result.AssemblyAttempts)
	}
	if result.Owner == nil || *result.Owner != "owner-1" {
		t.Errorf("expected Owner=owner-1, got %v", result.Owner)
	}

	// Second lock should fail (already processing) — a different caller
	// can't win the same CAS.
	locked, err = repo.TryLockForProcessing(ctx, "lock-test", testLease("owner-2"))
	if err != nil {
		t.Fatalf("TryLockForProcessing failed: %v", err)
	}
	if locked {
		t.Error("expected second lock to fail")
	}
}

// TestPartialUploadRepository_PublishAssembly_FailAssembly exercises the
// ADR-016 Publish and Fail transitions, including the owner-fencing
// invariant: a stale attempt (wrong owner, e.g. after a takeover) must never
// be able to publish or fail a row it no longer owns.
func TestPartialUploadRepository_PublishAssembly_FailAssembly(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()
	now := time.Now()

	newUpload := func(id string) *models.PartialUpload {
		u := &models.PartialUpload{
			UploadID: id, Filename: "test.txt", TotalSize: 1024, ChunkSize: 256,
			TotalChunks: 4, Status: "uploading", MaxDownloads: 3,
			CreatedAt: now, LastActivity: now,
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		return u
	}

	t.Run("publish success", func(t *testing.T) {
		id := "publish-ok"
		newUpload(id)
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("owner-a")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		file := &models.File{
			ClaimCode: "CLAIMPUB1", OriginalFilename: "test.txt", StoredFilename: "stored-1",
			FileSize: 1024, MimeType: "text/plain", ExpiresAt: now.Add(24 * time.Hour),
		}
		if err := repo.PublishAssembly(ctx, id, "owner-a", file); err != nil {
			t.Fatalf("PublishAssembly failed: %v", err)
		}
		if file.ID == 0 {
			t.Error("expected file.ID to be set after publish")
		}

		result, _ := repo.GetByUploadID(ctx, id)
		if result.Status != "completed" || !result.Completed {
			t.Errorf("expected completed, got status=%s completed=%v", result.Status, result.Completed)
		}
		if result.ClaimCode == nil || *result.ClaimCode != "CLAIMPUB1" {
			t.Error("expected ClaimCode=CLAIMPUB1")
		}
		if result.AssemblyCompletedAt == nil {
			t.Error("expected AssemblyCompletedAt to be set")
		}

		var gotPartialUploadID sql.NullString
		if err := db.QueryRow(`SELECT partial_upload_id FROM files WHERE id = ?`, file.ID).Scan(&gotPartialUploadID); err != nil {
			t.Fatalf("query files: %v", err)
		}
		if !gotPartialUploadID.Valid || gotPartialUploadID.String != id {
			t.Errorf("expected files.partial_upload_id=%s, got %v", id, gotPartialUploadID)
		}
	})

	t.Run("publish with wrong owner is lease lost", func(t *testing.T) {
		id := "publish-wrong-owner"
		newUpload(id)
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("owner-real")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		file := &models.File{
			ClaimCode: "CLAIMPUB2", OriginalFilename: "test.txt", StoredFilename: "stored-2",
			FileSize: 1024, MimeType: "text/plain", ExpiresAt: now.Add(24 * time.Hour),
		}
		err := repo.PublishAssembly(ctx, id, "owner-impostor", file)
		if !errors.Is(err, repository.ErrLeaseLost) {
			t.Fatalf("expected ErrLeaseLost, got %v", err)
		}
		result, _ := repo.GetByUploadID(ctx, id)
		if result.Status != "processing" {
			t.Errorf("row must be untouched by a failed publish, got status=%s", result.Status)
		}
	})

	t.Run("fail success retryable", func(t *testing.T) {
		id := "fail-retryable"
		newUpload(id)
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("owner-b")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		if err := repo.FailAssembly(ctx, id, "owner-b", "clamd unreachable", "SCAN_UNAVAILABLE", true, nil); err != nil {
			t.Fatalf("FailAssembly failed: %v", err)
		}
		result, _ := repo.GetByUploadID(ctx, id)
		if result.Status != "failed" {
			t.Errorf("expected status=failed, got %s", result.Status)
		}
		if !result.ErrorRetryable {
			t.Error("expected ErrorRetryable=true")
		}
		if result.ErrorCode == nil || *result.ErrorCode != "SCAN_UNAVAILABLE" {
			t.Errorf("expected ErrorCode=SCAN_UNAVAILABLE, got %v", result.ErrorCode)
		}
		if result.Owner != nil {
			t.Error("expected Owner cleared after fail")
		}
	})

	t.Run("fail terminal with audit file", func(t *testing.T) {
		id := "fail-malware"
		newUpload(id)
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("owner-c")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		audit := &models.File{
			ClaimCode: "CLAIMAUDIT", OriginalFilename: "test.txt", StoredFilename: "quarantined-1",
			FileSize: 0, MimeType: "application/octet-stream", ExpiresAt: now.Add(24 * time.Hour),
			ScanStatus: "infected", ScanResult: "Eicar-Test-Signature",
		}
		if err := repo.FailAssembly(ctx, id, "owner-c", "malware detected", "MALWARE_DETECTED", false, audit); err != nil {
			t.Fatalf("FailAssembly failed: %v", err)
		}
		if audit.ID == 0 {
			t.Error("expected audit file.ID to be set")
		}
		result, _ := repo.GetByUploadID(ctx, id)
		if result.ErrorRetryable {
			t.Error("expected ErrorRetryable=false for MALWARE_DETECTED")
		}
		if result.ClaimCode != nil {
			t.Error("expected partial_uploads.claim_code to stay unset on a failed (non-published) assembly")
		}
	})

	t.Run("fail with wrong owner is lease lost and no audit row inserted", func(t *testing.T) {
		id := "fail-wrong-owner"
		newUpload(id)
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("owner-real2")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		audit := &models.File{
			ClaimCode: "CLAIMSHOULDNOTEXIST", OriginalFilename: "test.txt", StoredFilename: "quarantined-2",
			FileSize: 0, MimeType: "application/octet-stream", ExpiresAt: now.Add(24 * time.Hour),
		}
		err := repo.FailAssembly(ctx, id, "owner-impostor2", "malware detected", "MALWARE_DETECTED", false, audit)
		if !errors.Is(err, repository.ErrLeaseLost) {
			t.Fatalf("expected ErrLeaseLost, got %v", err)
		}
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM files WHERE claim_code = ?`, "CLAIMSHOULDNOTEXIST").Scan(&count); err != nil {
			t.Fatalf("query files: %v", err)
		}
		if count != 0 {
			t.Error("expected no audit file row inserted when the owner fence rejects the transition")
		}
	})
}

// TestIsFilesPartialUploadIDViolation is a DB-review regression test: the
// generic "any UNIQUE violation on files" check used to map a claim_code
// collision (insertFile's OTHER unique constraint — a rare claim-code-
// generation race, unrelated to ADR-016 fencing) to the same
// ErrDuplicateKey as a genuine idx_files_partial_upload_id collision
// ("this upload was already published/failed by someone else"),
// conflating two very different situations. Exercises the real SQLite error
// text rather than a synthetic string, since modernc.org/sqlite's exact
// wording is what the substring check depends on.
func TestIsFilesPartialUploadIDViolation(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	ctx := context.Background()

	insert := func(claimCode string, partialUploadID *string) error {
		_, err := db.ExecContext(ctx, `
			INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, expires_at, partial_upload_id)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, claimCode, "f.txt", "stored-"+claimCode, 10, "text/plain", time.Now().Add(time.Hour).Format(time.RFC3339), partialUploadID)
		return err
	}

	pid := "dup-upload-id"
	if err := insert("CLAIMA", &pid); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	t.Run("partial_upload_id collision is detected", func(t *testing.T) {
		err := insert("CLAIMB", &pid) // same partial_upload_id, different claim_code
		if err == nil {
			t.Fatal("expected a unique constraint violation")
		}
		if !isFilesPartialUploadIDViolation(err) {
			t.Errorf("expected isFilesPartialUploadIDViolation=true for a partial_upload_id collision, got error: %v", err)
		}
	})

	t.Run("claim_code collision is not misreported", func(t *testing.T) {
		otherPid := "other-upload-id"
		err := insert("CLAIMA", &otherPid) // same claim_code as the first insert, different partial_upload_id
		if err == nil {
			t.Fatal("expected a unique constraint violation")
		}
		if isFilesPartialUploadIDViolation(err) {
			t.Errorf("a claim_code collision must not be misreported as a partial_upload_id violation: %v", err)
		}
	})
}

// TestPartialUploadRepository_LockFailedForProcessing verifies the combined
// Reopen-and-Lock transition (failed -> processing in one atomic step, ADR-016
// bug-hunter finding M2) only fires for a retryable failure under the
// attempt cap.
func TestPartialUploadRepository_LockFailedForProcessing(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()
	now := time.Now()

	mkFailed := func(id string, retryable bool) {
		u := &models.PartialUpload{
			UploadID: id, Filename: "test.txt", TotalSize: 1024, ChunkSize: 256,
			TotalChunks: 4, Status: "uploading", CreatedAt: now, LastActivity: now,
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("o")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		code := "ASSEMBLY_FAILED"
		if !retryable {
			code = "MALWARE_DETECTED"
		}
		if err := repo.FailAssembly(ctx, id, "o", "boom", code, retryable, nil); err != nil {
			t.Fatalf("FailAssembly: %v", err)
		}
	}

	t.Run("retryable under cap locks for processing", func(t *testing.T) {
		mkFailed("reopen-ok", true)
		ok, err := repo.LockFailedForProcessing(ctx, "reopen-ok", testLease("new-owner"), 5)
		if err != nil {
			t.Fatalf("LockFailedForProcessing: %v", err)
		}
		if !ok {
			t.Fatal("expected lock to succeed")
		}
		result, _ := repo.GetByUploadID(ctx, "reopen-ok")
		if result.Status != "processing" {
			t.Errorf("expected status=processing (not uploading — M2 fix), got %s", result.Status)
		}
		if result.Owner == nil || *result.Owner != "new-owner" {
			t.Errorf("expected Owner=new-owner, got %v", result.Owner)
		}
		if result.AssemblyAttempts != 2 {
			t.Errorf("expected AssemblyAttempts=2 (1 from the original failure + 1 from this lock), got %d", result.AssemblyAttempts)
		}
		if result.ErrorCode != nil || result.ErrorMessage != nil {
			t.Error("expected error fields cleared after locking")
		}
	})

	t.Run("terminal does not lock", func(t *testing.T) {
		mkFailed("reopen-terminal", false)
		ok, err := repo.LockFailedForProcessing(ctx, "reopen-terminal", testLease("new-owner"), 5)
		if err != nil {
			t.Fatalf("LockFailedForProcessing: %v", err)
		}
		if ok {
			t.Error("expected terminal failure not to lock")
		}
		result, _ := repo.GetByUploadID(ctx, "reopen-terminal")
		if result.Status != "failed" {
			t.Errorf("expected row to remain failed, got %s", result.Status)
		}
	})

	t.Run("at attempt cap does not lock", func(t *testing.T) {
		mkFailed("reopen-exhausted", true)
		ok, err := repo.LockFailedForProcessing(ctx, "reopen-exhausted", testLease("new-owner"), 1) // attempts already = 1
		if err != nil {
			t.Fatalf("LockFailedForProcessing: %v", err)
		}
		if ok {
			t.Error("expected lock at attempt cap to fail")
		}
		result, _ := repo.GetByUploadID(ctx, "reopen-exhausted")
		if result.Status != "failed" {
			t.Errorf("expected row to remain failed, got %s", result.Status)
		}
	})
}

// TestPartialUploadRepository_TakeOverExpiredLease_ExhaustExpiredLease
// covers the recovery-side transitions: TakeOver only matches an
// unexpired-lease-free row under the attempt cap, and Exhaust only matches
// once the cap is reached.
func TestPartialUploadRepository_TakeOverExpiredLease_ExhaustExpiredLease(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()
	now := time.Now()

	newLocked := func(id string) {
		u := &models.PartialUpload{
			UploadID: id, Filename: "test.txt", TotalSize: 1024, ChunkSize: 256,
			TotalChunks: 4, Status: "uploading", CreatedAt: now, LastActivity: now,
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	t.Run("cannot take over a live lease", func(t *testing.T) {
		id := "takeover-live"
		newLocked(id)
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("live-owner")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		took, err := repo.TakeOverExpiredLease(ctx, id, testLease("thief"), 5)
		if err != nil {
			t.Fatalf("TakeOverExpiredLease: %v", err)
		}
		if took {
			t.Error("expected takeover of a live (unexpired) lease to fail")
		}
	})

	t.Run("takes over an expired lease and bumps attempts", func(t *testing.T) {
		id := "takeover-expired"
		newLocked(id)
		if _, err := repo.TryLockForProcessing(ctx, id, repository.AssemblyLease{Owner: "dead-owner", TTL: 1}); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		time.Sleep(1100 * time.Millisecond) // let the 1s lease expire

		took, err := repo.TakeOverExpiredLease(ctx, id, testLease("rescuer"), 5)
		if err != nil {
			t.Fatalf("TakeOverExpiredLease: %v", err)
		}
		if !took {
			t.Fatal("expected takeover of an expired lease to succeed")
		}
		result, _ := repo.GetByUploadID(ctx, id)
		if result.Owner == nil || *result.Owner != "rescuer" {
			t.Errorf("expected Owner=rescuer, got %v", result.Owner)
		}
		if result.AssemblyAttempts != 2 {
			t.Errorf("expected AssemblyAttempts=2 after takeover, got %d", result.AssemblyAttempts)
		}
	})

	t.Run("exhausts at attempt cap instead of taking over", func(t *testing.T) {
		id := "exhaust-at-cap"
		newLocked(id)
		if _, err := repo.TryLockForProcessing(ctx, id, repository.AssemblyLease{Owner: "dead-owner", TTL: 1}); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		time.Sleep(1100 * time.Millisecond)

		// maxAttempts=1: current assembly_attempts (1) is already >= cap.
		took, err := repo.TakeOverExpiredLease(ctx, id, testLease("rescuer"), 1)
		if err != nil {
			t.Fatalf("TakeOverExpiredLease: %v", err)
		}
		if took {
			t.Error("expected takeover to refuse once attempts >= max")
		}

		exhausted, err := repo.ExhaustExpiredLease(ctx, id, 1)
		if err != nil {
			t.Fatalf("ExhaustExpiredLease: %v", err)
		}
		if !exhausted {
			t.Fatal("expected exhaust to succeed once attempts >= max")
		}
		result, _ := repo.GetByUploadID(ctx, id)
		if result.Status != "failed" {
			t.Errorf("expected status=failed, got %s", result.Status)
		}
		if result.ErrorRetryable {
			t.Error("expected ErrorRetryable=false for ASSEMBLY_RETRIES_EXHAUSTED")
		}
		if result.ErrorCode == nil || *result.ErrorCode != "ASSEMBLY_RETRIES_EXHAUSTED" {
			t.Errorf("expected ErrorCode=ASSEMBLY_RETRIES_EXHAUSTED, got %v", result.ErrorCode)
		}
	})
}

// TestPartialUploadRepository_RenewYieldGetExpiredLeases covers the
// heartbeat (Renew), shutdown (Yield), and recovery-scan (GetExpiredLeases)
// operations.
func TestPartialUploadRepository_RenewYieldGetExpiredLeases(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()
	now := time.Now()

	mk := func(id string) {
		u := &models.PartialUpload{
			UploadID: id, Filename: "test.txt", TotalSize: 1024, ChunkSize: 256,
			TotalChunks: 4, Status: "uploading", CreatedAt: now, LastActivity: now,
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	t.Run("renew extends a live lease, wrong owner does not", func(t *testing.T) {
		id := "renew-test"
		mk(id)
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("renew-owner")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		ok, err := repo.RenewAssemblyLease(ctx, id, testLease("renew-owner"))
		if err != nil {
			t.Fatalf("RenewAssemblyLease: %v", err)
		}
		if !ok {
			t.Error("expected renew by the true owner to succeed")
		}
		ok, err = repo.RenewAssemblyLease(ctx, id, testLease("impostor"))
		if err != nil {
			t.Fatalf("RenewAssemblyLease: %v", err)
		}
		if ok {
			t.Error("expected renew by a non-owner to fail")
		}
	})

	t.Run("yield expires the lease immediately for the true owner only", func(t *testing.T) {
		id := "yield-test"
		mk(id)
		if _, err := repo.TryLockForProcessing(ctx, id, testLease("yield-owner")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		if err := repo.YieldAssemblyLease(ctx, id, "yield-owner"); err != nil {
			t.Fatalf("YieldAssemblyLease: %v", err)
		}
		took, err := repo.TakeOverExpiredLease(ctx, id, testLease("recoverer"), 5)
		if err != nil {
			t.Fatalf("TakeOverExpiredLease: %v", err)
		}
		if !took {
			t.Error("expected a yielded lease to be immediately takeover-eligible")
		}
	})

	t.Run("GetExpiredLeases returns only processing rows with an expired lease", func(t *testing.T) {
		mk("expired-1")
		if _, err := repo.TryLockForProcessing(ctx, "expired-1", repository.AssemblyLease{Owner: "o1", TTL: 1}); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		mk("live-1")
		if _, err := repo.TryLockForProcessing(ctx, "live-1", testLease("o2")); err != nil {
			t.Fatalf("TryLockForProcessing: %v", err)
		}
		mk("uploading-1") // not processing at all

		time.Sleep(1100 * time.Millisecond)

		expired, err := repo.GetExpiredLeases(ctx, 0)
		if err != nil {
			t.Fatalf("GetExpiredLeases: %v", err)
		}
		found := false
		for _, u := range expired {
			if u.UploadID == "live-1" || u.UploadID == "uploading-1" {
				t.Errorf("GetExpiredLeases returned a row it shouldn't have: %s (status=%s)", u.UploadID, u.Status)
			}
			if u.UploadID == "expired-1" {
				found = true
			}
		}
		if !found {
			t.Error("expected expired-1 to be returned by GetExpiredLeases")
		}
	})
}

// TestPartialUploadRepository_ReleaseProcessingLock_NoClobber is the SH-1.4
// safety test: ReleaseProcessingLock must ONLY touch a row that's still
// "processing" under the given owner. A pre-fix implementation using an
// unconditional UpdateStatus could clobber a row that had already advanced
// to "completed" or "failed", enabling duplicate assembly + duplicate claim
// codes via a TOCTOU race.
//
// Per ADR-016 bug-hunter findings M2/L2, a successful release no longer
// reverts status to "uploading" — it stays "processing" with an
// immediately-expired lease (Yield-like) and a decremented attempt count,
// so the row is picked up by the next recovery sweep instead of only a
// client's own retry.
func TestPartialUploadRepository_ReleaseProcessingLock_NoClobber(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()
	now := time.Now()

	// Happy path: row in "processing" is released cleanly.
	processingUpload := &models.PartialUpload{
		UploadID:     "release-processing",
		Filename:     "p.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		Status:       "uploading",
		CreatedAt:    now,
		LastActivity: now,
	}
	if err := repo.Create(ctx, processingUpload); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.TryLockForProcessing(ctx, "release-processing", testLease("release-owner")); err != nil {
		t.Fatalf("TryLock: %v", err)
	}
	// A wrong-owner release must be a no-op (owner fencing applies here too).
	reverted, err := repo.ReleaseProcessingLock(ctx, "release-processing", "impostor")
	if err != nil {
		t.Fatalf("ReleaseProcessingLock: %v", err)
	}
	if reverted {
		t.Error("expected release by a non-owner to fail")
	}

	reverted, err = repo.ReleaseProcessingLock(ctx, "release-processing", "release-owner")
	if err != nil {
		t.Fatalf("ReleaseProcessingLock: %v", err)
	}
	if !reverted {
		t.Error("expected release to succeed")
	}
	got, _ := repo.GetByUploadID(ctx, "release-processing")
	if got.Status != "processing" {
		t.Errorf("after release, status = %q, want processing (M2/L2 fix — not uploading)", got.Status)
	}
	if got.AssemblyAttempts != 0 {
		t.Errorf("expected AssemblyAttempts reverted to 0, got %d", got.AssemblyAttempts)
	}
	// The lease must be immediately takeover-eligible.
	tookOver, err := repo.TakeOverExpiredLease(ctx, "release-processing", testLease("recovery-owner"), 5)
	if err != nil {
		t.Fatalf("TakeOverExpiredLease: %v", err)
	}
	if !tookOver {
		t.Error("expected the released lease to be immediately takeover-eligible")
	}

	// No-clobber: a row that has advanced to "completed" must NOT be
	// reverted, even if a stale unwind call comes in. This is the property
	// that prevents the SH-1.4 TOCTOU race from producing duplicate claim
	// codes.
	for _, terminalStatus := range []string{"completed", "failed"} {
		t.Run(terminalStatus, func(t *testing.T) {
			id := "release-noclobber-" + terminalStatus
			u := &models.PartialUpload{
				UploadID: id, Filename: "n.txt", TotalSize: 1024, ChunkSize: 256,
				TotalChunks: 4, Status: "uploading", CreatedAt: now, LastActivity: now,
			}
			if err := repo.Create(ctx, u); err != nil {
				t.Fatalf("Create: %v", err)
			}
			// Skip the intermediate steps and mark the upload terminal.
			if err := repo.UpdateStatus(ctx, id, terminalStatus, nil); err != nil {
				t.Fatalf("UpdateStatus: %v", err)
			}
			reverted, err := repo.ReleaseProcessingLock(ctx, id, "owner-doesnt-matter")
			if err != nil {
				t.Fatalf("ReleaseProcessingLock: %v", err)
			}
			if reverted {
				t.Errorf("ReleaseProcessingLock clobbered terminal status %q", terminalStatus)
			}
			got, _ := repo.GetByUploadID(ctx, id)
			if got.Status != terminalStatus {
				t.Errorf("after no-op release, status = %q, want %q", got.Status, terminalStatus)
			}
		})
	}
}

func TestPartialUploadRepository_GetByUserID(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	now := time.Now()
	userID := int64(42)

	// Create uploads for user
	for i := 0; i < 3; i++ {
		upload := &models.PartialUpload{
			UploadID:     "user-" + string(rune('A'+i)),
			UserID:       &userID,
			Filename:     "test.txt",
			TotalSize:    1024,
			ChunkSize:    256,
			TotalChunks:  4,
			CreatedAt:    now,
			LastActivity: now,
		}
		_ = repo.Create(ctx, upload)
	}

	// Create upload for different user
	otherUserID := int64(99)
	otherUpload := &models.PartialUpload{
		UploadID:     "other-user",
		UserID:       &otherUserID,
		Filename:     "other.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, otherUpload)

	// Get uploads for user 42
	uploads, err := repo.GetByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByUserID failed: %v", err)
	}
	if len(uploads) != 3 {
		t.Errorf("expected 3 uploads, got %d", len(uploads))
	}
}

func TestPartialUploadRepository_ImplementsInterface(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()

	var _ repository.PartialUploadRepository = NewPartialUploadRepository(db)
}
