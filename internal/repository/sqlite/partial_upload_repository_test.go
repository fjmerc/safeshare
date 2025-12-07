package sqlite

import (
	"context"
	"database/sql"
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
			assembly_completed_at TEXT
		)
	`)
	if err != nil {
		t.Fatalf("failed to create partial_uploads table: %v", err)
	}

	// Create files table (needed for quota check)
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
			user_id INTEGER
		)
	`)
	if err != nil {
		t.Fatalf("failed to create files table: %v", err)
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

func TestPartialUploadRepository_MarkCompleted(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:     "complete-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// Mark completed
	err := repo.MarkCompleted(ctx, "complete-test", "CLAIM123")
	if err != nil {
		t.Fatalf("MarkCompleted failed: %v", err)
	}

	// Verify completion
	result, _ := repo.GetByUploadID(ctx, "complete-test")
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	if result.ClaimCode == nil || *result.ClaimCode != "CLAIM123" {
		t.Error("expected ClaimCode=CLAIM123")
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

func TestPartialUploadRepository_SetAssemblyStarted(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:     "assembly-start-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// Set assembly started
	err := repo.SetAssemblyStarted(ctx, "assembly-start-test")
	if err != nil {
		t.Fatalf("SetAssemblyStarted failed: %v", err)
	}

	result, _ := repo.GetByUploadID(ctx, "assembly-start-test")
	if result.Status != "processing" {
		t.Errorf("expected status=processing, got %s", result.Status)
	}
	if result.AssemblyStartedAt == nil {
		t.Error("expected AssemblyStartedAt to be set")
	}
}

func TestPartialUploadRepository_SetAssemblyCompleted(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:     "assembly-complete-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// Set assembly completed
	err := repo.SetAssemblyCompleted(ctx, "assembly-complete-test", "CLAIM456")
	if err != nil {
		t.Fatalf("SetAssemblyCompleted failed: %v", err)
	}

	result, _ := repo.GetByUploadID(ctx, "assembly-complete-test")
	if result.Status != "completed" {
		t.Errorf("expected status=completed, got %s", result.Status)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	if result.ClaimCode == nil || *result.ClaimCode != "CLAIM456" {
		t.Error("expected ClaimCode=CLAIM456")
	}
	if result.AssemblyCompletedAt == nil {
		t.Error("expected AssemblyCompletedAt to be set")
	}
}

func TestPartialUploadRepository_SetAssemblyFailed(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create an upload
	now := time.Now()
	upload := &models.PartialUpload{
		UploadID:     "assembly-fail-test",
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    256,
		TotalChunks:  4,
		CreatedAt:    now,
		LastActivity: now,
	}
	_ = repo.Create(ctx, upload)

	// Set assembly failed
	err := repo.SetAssemblyFailed(ctx, "assembly-fail-test", "checksum mismatch")
	if err != nil {
		t.Fatalf("SetAssemblyFailed failed: %v", err)
	}

	result, _ := repo.GetByUploadID(ctx, "assembly-fail-test")
	if result.Status != "failed" {
		t.Errorf("expected status=failed, got %s", result.Status)
	}
	if result.ErrorMessage == nil || *result.ErrorMessage != "checksum mismatch" {
		t.Error("expected ErrorMessage='checksum mismatch'")
	}
}

func TestPartialUploadRepository_GetProcessing(t *testing.T) {
	db := setupPartialUploadTestDB(t)
	defer db.Close()
	repo := NewPartialUploadRepository(db)
	ctx := context.Background()

	// Create uploads with different statuses
	now := time.Now()
	for _, status := range []string{"uploading", "processing", "processing", "completed"} {
		upload := &models.PartialUpload{
			UploadID:     "proc-" + status + "-" + now.Format(time.RFC3339Nano),
			Filename:     "test.txt",
			TotalSize:    1024,
			ChunkSize:    256,
			TotalChunks:  4,
			Status:       status,
			CreatedAt:    now,
			LastActivity: now,
		}
		_ = repo.Create(ctx, upload)
		now = now.Add(1 * time.Millisecond) // Ensure unique IDs
	}

	processing, err := repo.GetProcessing(ctx)
	if err != nil {
		t.Fatalf("GetProcessing failed: %v", err)
	}
	if len(processing) != 2 {
		t.Errorf("expected 2 processing uploads, got %d", len(processing))
	}
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

	// First lock should succeed
	locked, err := repo.TryLockForProcessing(ctx, "lock-test")
	if err != nil {
		t.Fatalf("TryLockForProcessing failed: %v", err)
	}
	if !locked {
		t.Error("expected first lock to succeed")
	}

	// Second lock should fail (already processing)
	locked, err = repo.TryLockForProcessing(ctx, "lock-test")
	if err != nil {
		t.Fatalf("TryLockForProcessing failed: %v", err)
	}
	if locked {
		t.Error("expected second lock to fail")
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
