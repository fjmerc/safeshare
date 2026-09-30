package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"

	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	// Register the process-wide connection-pragma hook (PRAGMA
	// foreign_keys = ON, etc.) before opening, so this test DB enforces the
	// same FK constraints production connections do (T36).
	database.EnsureConnectionHook()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	// Force single connection for in-memory databases
	db.SetMaxOpenConns(1)

	// Run migrations to create schema
	if err := database.RunMigrations(db); err != nil {
		db.Close()
		t.Fatalf("failed to run migrations: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func TestFileRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// files.user_id has a real FK to users(id), enforced now that setupTestDB
	// enables PRAGMA foreign_keys (T36) — a dangling reference to a
	// nonexistent user id is rejected, so create a real one.
	user, err := NewUserRepository(db).Create(ctx, "filecreatetest-user", "filecreatetest@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	maxDownloads := 5
	userID := user.ID
	file := &models.File{
		ClaimCode:        "TEST123",
		OriginalFilename: "test.txt",
		StoredFilename:   "stored-uuid.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDownloads,
		UploaderIP:       "192.168.1.1",
		PasswordHash:     "hashed_password",
		UserID:           &userID,
	}

	err = repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if file.ID == 0 {
		t.Error("Create() did not set file ID")
	}

	// Verify file was inserted
	retrieved, err := repo.GetByClaimCode(ctx, "TEST123")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("GetByClaimCode() returned nil")
	}

	if retrieved.ClaimCode != "TEST123" {
		t.Errorf("ClaimCode = %q, want %q", retrieved.ClaimCode, "TEST123")
	}

	if retrieved.OriginalFilename != "test.txt" {
		t.Errorf("OriginalFilename = %q, want %q", retrieved.OriginalFilename, "test.txt")
	}

	if retrieved.FileSize != 1024 {
		t.Errorf("FileSize = %d, want 1024", retrieved.FileSize)
	}
}

func TestFileRepository_GetByID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create a file first
	file := &models.File{
		ClaimCode:        "GETBYID123",
		OriginalFilename: "test.txt",
		StoredFilename:   "stored-getbyid.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Get by ID
	retrieved, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID() error: %v", err)
	}

	if retrieved.ClaimCode != "GETBYID123" {
		t.Errorf("ClaimCode = %q, want %q", retrieved.ClaimCode, "GETBYID123")
	}
}

func TestFileRepository_GetByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	_, err := repo.GetByID(ctx, 99999)
	if err != repository.ErrNotFound {
		t.Errorf("GetByID() error = %v, want ErrNotFound", err)
	}
}

func TestFileRepository_GetByClaimCode_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	file, err := repo.GetByClaimCode(ctx, "NOTEXIST")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}

	if file != nil {
		t.Error("GetByClaimCode() should return nil for non-existent file")
	}
}

func TestFileRepository_GetByClaimCode_Expired(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create an expired file
	file := &models.File{
		ClaimCode:        "EXPIRED123",
		OriginalFilename: "expired.txt",
		StoredFilename:   "stored-expired.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Attempt to retrieve expired file
	retrieved, err := repo.GetByClaimCode(ctx, "EXPIRED123")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}

	if retrieved != nil {
		t.Error("GetByClaimCode() should return nil for expired file")
	}
}

func TestFileRepository_IncrementDownloadCount(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create a file
	file := &models.File{
		ClaimCode:        "DOWNLOAD123",
		OriginalFilename: "download.txt",
		StoredFilename:   "stored-download.txt",
		FileSize:         256,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Increment download count
	err = repo.IncrementDownloadCount(ctx, file.ID)
	if err != nil {
		t.Fatalf("IncrementDownloadCount() error: %v", err)
	}

	// Verify count increased
	retrieved, err := repo.GetByClaimCode(ctx, "DOWNLOAD123")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}

	if retrieved.DownloadCount != 1 {
		t.Errorf("DownloadCount = %d, want 1", retrieved.DownloadCount)
	}
}

func TestFileRepository_IncrementDownloadCount_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	err := repo.IncrementDownloadCount(ctx, 99999)
	if err != repository.ErrNotFound {
		t.Errorf("IncrementDownloadCount() error = %v, want ErrNotFound", err)
	}
}

func TestFileRepository_TryIncrementDownloadWithLimit_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	maxDownloads := 5
	file := &models.File{
		ClaimCode:        "DOWNLOAD_LIMIT1",
		OriginalFilename: "limited.txt",
		StoredFilename:   "stored-limited.txt",
		FileSize:         1000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDownloads,
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Try to increment (should succeed - 0 < 5)
	success, err := repo.TryIncrementDownloadWithLimit(ctx, file.ID, "DOWNLOAD_LIMIT1")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit() error: %v", err)
	}

	if !success {
		t.Error("TryIncrementDownloadWithLimit() should succeed when under limit")
	}
}

func TestFileRepository_TryIncrementDownloadWithLimit_LimitReached(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	maxDownloads := 1
	file := &models.File{
		ClaimCode:        "LIMIT_TEST",
		OriginalFilename: "test.txt",
		StoredFilename:   "stored-test.txt",
		FileSize:         500,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDownloads,
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// First increment should succeed
	success, err := repo.TryIncrementDownloadWithLimit(ctx, file.ID, "LIMIT_TEST")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit() error: %v", err)
	}
	if !success {
		t.Error("First increment should succeed")
	}

	// Second increment should fail (limit reached)
	success, err = repo.TryIncrementDownloadWithLimit(ctx, file.ID, "LIMIT_TEST")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit() error: %v", err)
	}
	if success {
		t.Error("TryIncrementDownloadWithLimit() should fail when limit reached")
	}
}

func TestFileRepository_TryIncrementDownloadWithLimit_WrongClaimCode(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	maxDownloads := 5
	file := &models.File{
		ClaimCode:        "CORRECT_CODE",
		OriginalFilename: "secure.txt",
		StoredFilename:   "stored-secure.txt",
		FileSize:         500,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDownloads,
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Try with wrong claim code
	_, err = repo.TryIncrementDownloadWithLimit(ctx, file.ID, "WRONG_CODE")
	if err != repository.ErrClaimCodeChanged {
		t.Errorf("TryIncrementDownloadWithLimit() error = %v, want ErrClaimCodeChanged", err)
	}
}

func TestFileRepository_Delete(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	file := &models.File{
		ClaimCode:        "DELETE123",
		OriginalFilename: "delete.txt",
		StoredFilename:   "stored-delete.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = repo.Delete(ctx, file.ID)
	if err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// Verify file is gone
	retrieved, err := repo.GetByClaimCode(ctx, "DELETE123")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}
	if retrieved != nil {
		t.Error("File should be deleted")
	}
}

func TestFileRepository_Delete_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	err := repo.Delete(ctx, 99999)
	if err != repository.ErrNotFound {
		t.Errorf("Delete() error = %v, want ErrNotFound", err)
	}
}

func TestFileRepository_DeleteByClaimCode(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	file := &models.File{
		ClaimCode:        "DELETEBY123",
		OriginalFilename: "delete.txt",
		StoredFilename:   "stored-deleteby.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	deletedFile, err := repo.DeleteByClaimCode(ctx, "DELETEBY123")
	if err != nil {
		t.Fatalf("DeleteByClaimCode() error: %v", err)
	}

	if deletedFile.ClaimCode != "DELETEBY123" {
		t.Errorf("DeleteByClaimCode() returned wrong file: %s", deletedFile.ClaimCode)
	}

	// Verify file is gone
	retrieved, err := repo.GetByClaimCode(ctx, "DELETEBY123")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}
	if retrieved != nil {
		t.Error("File should be deleted")
	}
}

func TestFileRepository_DeleteByClaimCode_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	_, err := repo.DeleteByClaimCode(ctx, "NOTEXIST")
	if err != repository.ErrNotFound {
		t.Errorf("DeleteByClaimCode() error = %v, want ErrNotFound", err)
	}
}

func TestFileRepository_DeleteByClaimCodes(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create multiple files
	for i := 1; i <= 3; i++ {
		file := &models.File{
			ClaimCode:        "BULK" + string(rune('0'+i)),
			OriginalFilename: "bulk.txt",
			StoredFilename:   "stored-bulk" + string(rune('0'+i)) + ".txt",
			FileSize:         512,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "192.168.1.1",
		}
		err := repo.Create(ctx, file)
		if err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	// Delete two of them
	deletedFiles, err := repo.DeleteByClaimCodes(ctx, []string{"BULK1", "BULK2"})
	if err != nil {
		t.Fatalf("DeleteByClaimCodes() error: %v", err)
	}

	if len(deletedFiles) != 2 {
		t.Errorf("DeleteByClaimCodes() returned %d files, want 2", len(deletedFiles))
	}

	// Verify BULK3 still exists
	retrieved, err := repo.GetByClaimCode(ctx, "BULK3")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}
	if retrieved == nil {
		t.Error("BULK3 should still exist")
	}
}

func TestFileRepository_CreateWithQuotaCheck_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	file := &models.File{
		ClaimCode:        "QUOTA1",
		OriginalFilename: "quota.txt",
		StoredFilename:   "stored-quota.txt",
		FileSize:         1000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	quotaLimit := int64(10000) // 10KB limit
	err := repo.CreateWithQuotaCheck(ctx, file, quotaLimit)
	if err != nil {
		t.Fatalf("CreateWithQuotaCheck() error: %v", err)
	}

	if file.ID == 0 {
		t.Error("CreateWithQuotaCheck() did not set file ID")
	}
}

func TestFileRepository_CreateWithQuotaCheck_ExceedsQuota(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create file using 900 bytes
	existingFile := &models.File{
		ClaimCode:        "EXISTING1",
		OriginalFilename: "existing.txt",
		StoredFilename:   "stored-existing.txt",
		FileSize:         900,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}
	err := repo.Create(ctx, existingFile)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Try to create file that would exceed quota
	newFile := &models.File{
		ClaimCode:        "EXCEED1",
		OriginalFilename: "exceed.txt",
		StoredFilename:   "stored-exceed.txt",
		FileSize:         200, // 900 + 200 > 1000
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	quotaLimit := int64(1000)
	err = repo.CreateWithQuotaCheck(ctx, newFile, quotaLimit)
	if err != repository.ErrQuotaExceeded {
		t.Errorf("CreateWithQuotaCheck() error = %v, want ErrQuotaExceeded", err)
	}
}

func TestFileRepository_GetTotalUsage(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Test with empty database
	usage, err := repo.GetTotalUsage(ctx)
	if err != nil {
		t.Fatalf("GetTotalUsage() error: %v", err)
	}

	if usage != 0 {
		t.Errorf("GetTotalUsage() = %d, want 0 for empty database", usage)
	}

	// Create active files
	for i := 1; i <= 3; i++ {
		file := &models.File{
			ClaimCode:        "USAGE" + string(rune('0'+i)),
			OriginalFilename: "usage.txt",
			StoredFilename:   "stored-usage" + string(rune('0'+i)) + ".txt",
			FileSize:         int64(1000 * i),
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "192.168.1.1",
		}
		err := repo.Create(ctx, file)
		if err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	// Get total usage (should be 1000 + 2000 + 3000 = 6000)
	usage, err = repo.GetTotalUsage(ctx)
	if err != nil {
		t.Fatalf("GetTotalUsage() error: %v", err)
	}

	expectedUsage := int64(6000)
	if usage != expectedUsage {
		t.Errorf("GetTotalUsage() = %d, want %d", usage, expectedUsage)
	}
}

func TestFileRepository_GetStats(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create some files
	for i := 1; i <= 2; i++ {
		file := &models.File{
			ClaimCode:        "STAT" + string(rune('0'+i)),
			OriginalFilename: "stat.txt",
			StoredFilename:   "stored-stat" + string(rune('0'+i)) + ".txt",
			FileSize:         int64(500 * i),
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "192.168.1.1",
		}
		err := repo.Create(ctx, file)
		if err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	stats, err := repo.GetStats(ctx, "")
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}

	if stats.TotalFiles != 2 {
		t.Errorf("TotalFiles = %d, want 2", stats.TotalFiles)
	}

	expectedStorage := int64(1500) // 500 + 1000
	if stats.StorageUsed != expectedStorage {
		t.Errorf("StorageUsed = %d, want %d", stats.StorageUsed, expectedStorage)
	}
}

func TestFileRepository_GetAll(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create files (including expired)
	files := []struct {
		claimCode string
		expired   bool
	}{
		{"ALL1", false},
		{"ALL2", false},
		{"ALL3", true},
	}

	for _, f := range files {
		expiresAt := time.Now().Add(24 * time.Hour)
		if f.expired {
			expiresAt = time.Now().Add(-1 * time.Hour)
		}

		file := &models.File{
			ClaimCode:        f.claimCode,
			OriginalFilename: "all.txt",
			StoredFilename:   "stored-" + f.claimCode + ".txt",
			FileSize:         512,
			MimeType:         "text/plain",
			ExpiresAt:        expiresAt,
			UploaderIP:       "192.168.1.1",
		}
		err := repo.Create(ctx, file)
		if err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	// GetAll should return all files including expired
	allFiles, err := repo.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll() error: %v", err)
	}

	if len(allFiles) != 3 {
		t.Errorf("GetAll() returned %d files, want 3 (including expired)", len(allFiles))
	}
}

func TestFileRepository_GetAllStoredFilenames(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create files
	storedNames := []string{"uuid-111.bin", "uuid-222.bin", "uuid-333.txt"}
	for i, name := range storedNames {
		file := &models.File{
			ClaimCode:        "STORED" + string(rune('0'+i)),
			OriginalFilename: "test.txt",
			StoredFilename:   name,
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		}
		if err := repo.Create(ctx, file); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	filenames, err := repo.GetAllStoredFilenames(ctx)
	if err != nil {
		t.Fatalf("GetAllStoredFilenames() error: %v", err)
	}

	if len(filenames) != 3 {
		t.Errorf("Expected 3 filenames, got %d", len(filenames))
	}

	for _, name := range storedNames {
		if !filenames[name] {
			t.Errorf("Expected to find %s in filenames map", name)
		}
	}
}

func TestFileRepository_DeleteExpired(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create temporary upload directory
	tmpDir, err := os.MkdirTemp("", "test-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create expired file (expired 2 hours ago to account for 1-hour grace period)
	expiredFile := &models.File{
		ClaimCode:        "EXPIRED1",
		OriginalFilename: "expired1.txt",
		StoredFilename:   "stored-expired1.txt",
		FileSize:         100,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-2 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = repo.Create(ctx, expiredFile)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Create physical file for expired file
	expiredPath := filepath.Join(tmpDir, expiredFile.StoredFilename)
	err = os.WriteFile(expiredPath, []byte("expired content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create active file
	activeFile := &models.File{
		ClaimCode:        "ACTIVE1",
		OriginalFilename: "active1.txt",
		StoredFilename:   "stored-active1.txt",
		FileSize:         200,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = repo.Create(ctx, activeFile)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Delete expired files
	deletedCount, err := repo.DeleteExpired(ctx, tmpDir, nil)
	if err != nil {
		t.Fatalf("DeleteExpired() error: %v", err)
	}

	if deletedCount != 1 {
		t.Errorf("DeleteExpired() deleted %d files, want 1", deletedCount)
	}

	// Verify expired physical file is deleted
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Error("Expired physical file should be deleted")
	}

	// Verify active file still exists in database
	retrieved, err := repo.GetByClaimCode(ctx, "ACTIVE1")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}
	if retrieved == nil {
		t.Error("Active file should still exist in database")
	}
}

func TestFileRepository_GetAllForAdmin(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create some files
	for i := 1; i <= 5; i++ {
		file := &models.File{
			ClaimCode:        "ADMIN" + string(rune('0'+i)),
			OriginalFilename: "admin.txt",
			StoredFilename:   "stored-admin" + string(rune('0'+i)) + ".txt",
			FileSize:         512,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "192.168.1.1",
		}
		err := repo.Create(ctx, file)
		if err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	// Get first page
	files, total, err := repo.GetAllForAdmin(ctx, 3, 0)
	if err != nil {
		t.Fatalf("GetAllForAdmin() error: %v", err)
	}

	if total != 5 {
		t.Errorf("Total = %d, want 5", total)
	}

	if len(files) != 3 {
		t.Errorf("Got %d files, want 3", len(files))
	}
}

func TestFileRepository_SearchForAdmin(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create files with different names
	files := []struct {
		claimCode string
		filename  string
	}{
		{"SEARCH1", "document.pdf"},
		{"SEARCH2", "image.png"},
		{"SEARCH3", "document_backup.pdf"},
	}

	for _, f := range files {
		file := &models.File{
			ClaimCode:        f.claimCode,
			OriginalFilename: f.filename,
			StoredFilename:   "stored-" + f.claimCode + ".txt",
			FileSize:         512,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "192.168.1.1",
		}
		err := repo.Create(ctx, file)
		if err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	// Search for "document"
	results, total, err := repo.SearchForAdmin(ctx, "document", 10, 0)
	if err != nil {
		t.Fatalf("SearchForAdmin() error: %v", err)
	}

	if total != 2 {
		t.Errorf("Total = %d, want 2", total)
	}

	if len(results) != 2 {
		t.Errorf("Got %d results, want 2", len(results))
	}
}

func TestFileRepository_SearchForAdmin_EscapesWildcards(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create file with literal % in name
	file := &models.File{
		ClaimCode:        "PERCENT1",
		OriginalFilename: "100%_complete.txt",
		StoredFilename:   "stored-percent.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}
	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Create another file
	file2 := &models.File{
		ClaimCode:        "OTHER1",
		OriginalFilename: "other.txt",
		StoredFilename:   "stored-other.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}
	err = repo.Create(ctx, file2)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Search for "100%" - should only find the file with literal %
	results, total, err := repo.SearchForAdmin(ctx, "100%", 10, 0)
	if err != nil {
		t.Fatalf("SearchForAdmin() error: %v", err)
	}

	if total != 1 {
		t.Errorf("Total = %d, want 1 (should escape %% wildcard)", total)
	}

	if len(results) != 1 || results[0].ClaimCode != "PERCENT1" {
		t.Error("Should find only the file with literal % in name")
	}
}

func TestFileRepository_IncrementCompletedDownloads(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	file := &models.File{
		ClaimCode:        "COMPLETED1",
		OriginalFilename: "completed.txt",
		StoredFilename:   "stored-completed.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = repo.IncrementCompletedDownloads(ctx, file.ID)
	if err != nil {
		t.Fatalf("IncrementCompletedDownloads() error: %v", err)
	}

	retrieved, err := repo.GetByClaimCode(ctx, "COMPLETED1")
	if err != nil {
		t.Fatalf("GetByClaimCode() error: %v", err)
	}

	if retrieved.CompletedDownloads != 1 {
		t.Errorf("CompletedDownloads = %d, want 1", retrieved.CompletedDownloads)
	}
}

func TestFileRepository_IncrementDownloadCountIfUnchanged(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	file := &models.File{
		ClaimCode:        "UNCHANGED1",
		OriginalFilename: "unchanged.txt",
		StoredFilename:   "stored-unchanged.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Should succeed with correct claim code
	err = repo.IncrementDownloadCountIfUnchanged(ctx, file.ID, "UNCHANGED1")
	if err != nil {
		t.Fatalf("IncrementDownloadCountIfUnchanged() error: %v", err)
	}

	// Should fail with wrong claim code
	err = repo.IncrementDownloadCountIfUnchanged(ctx, file.ID, "WRONG")
	if err != repository.ErrClaimCodeChanged {
		t.Errorf("IncrementDownloadCountIfUnchanged() error = %v, want ErrClaimCodeChanged", err)
	}
}

// Test pagination bounds validation
func TestFileRepository_GetAllForAdmin_BoundsValidation(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()

	// Create a file
	file := &models.File{
		ClaimCode:        "BOUNDS1",
		OriginalFilename: "bounds.txt",
		StoredFilename:   "stored-bounds.txt",
		FileSize:         512,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}
	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Test with negative values (should be normalized)
	files, _, err := repo.GetAllForAdmin(ctx, -1, -1)
	if err != nil {
		t.Fatalf("GetAllForAdmin() with negative values should not error: %v", err)
	}

	// With limit=0 (normalized from -1), should return empty
	if len(files) != 0 {
		t.Errorf("GetAllForAdmin() with limit=0 should return empty, got %d", len(files))
	}
}

// --- ADR-014 download-session tests -----------------------------------------
//
// These exercise the SQLite implementation of the Reserve/Lookup/Commit/
// Touch/Complete/Cancel/Reap session API directly, independent of the HTTP
// handler layer (see internal/handlers/claim_session_test.go for the
// end-to-end behaviour).

func createSessionTestFile(t *testing.T, repo *FileRepository, claimCode string, maxDL int) *models.File {
	t.Helper()
	file := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: "session-test.bin",
		StoredFilename:   "session-test-stored.bin",
		FileSize:         4096,
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDL,
		UploaderIP:       "127.0.0.1",
	}
	if err := repo.Create(context.Background(), file); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return file
}

// TestFileRepository_Delete_CascadesDownloadSessions verifies
// download_sessions.file_id ON DELETE CASCADE (T36): deleting a file with a
// live (uncommitted) download session must remove that session row too,
// rather than leaving a dangling reference.
func TestFileRepository_Delete_CascadesDownloadSessions(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sescascade", 1)

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	var before int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM download_sessions WHERE file_id = ?`, file.ID).Scan(&before); err != nil {
		t.Fatalf("count before delete: %v", err)
	}
	if before != 1 {
		t.Fatalf("download_sessions rows before delete = %d, want 1", before)
	}

	if err := repo.Delete(ctx, file.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	var after int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM download_sessions WHERE file_id = ?`, file.ID).Scan(&after); err != nil {
		t.Fatalf("count after delete: %v", err)
	}
	if after != 0 {
		t.Errorf("download_sessions rows after file delete = %d, want 0 (ON DELETE CASCADE)", after)
	}
}

// TestFileRepository_CommitDownloadSession_Idempotent — a second commit call
// against an already-committed session must report AlreadyCommitted and must
// not touch the counters again.
func TestFileRepository_CommitDownloadSession_Idempotent(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sesidem", 1)

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	result, err := repo.CommitDownloadSession(ctx, file.ID, token)
	if err != nil {
		t.Fatalf("first CommitDownloadSession: %v", err)
	}
	if result != repository.DownloadCommitCredited {
		t.Fatalf("first CommitDownloadSession result = %v, want Credited", result)
	}

	result, err = repo.CommitDownloadSession(ctx, file.ID, token)
	if err != nil {
		t.Fatalf("second CommitDownloadSession: %v", err)
	}
	if result != repository.DownloadCommitAlreadyCommitted {
		t.Errorf("second CommitDownloadSession result = %v, want AlreadyCommitted", result)
	}

	got, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (idempotent)", got.DownloadCount)
	}
}

// TestFileRepository_CancelDownload_NoOpAfterCommit — Cancel after a
// successful Commit must not touch counters or resurrect the row.
func TestFileRepository_CancelDownload_NoOpAfterCommit(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sescancel", 1)

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if _, err := repo.CommitDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CommitDownloadSession: %v", err)
	}

	if err := repo.CancelDownload(ctx, file.ID, token); err != nil {
		t.Fatalf("CancelDownload after commit: %v", err)
	}

	got, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (Cancel-after-Commit must be a no-op)", got.DownloadCount)
	}

	// The slot must still be genuinely taken — a fresh Reserve on this
	// max_downloads=1 file must be denied.
	tok2, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("second ReserveDownload: %v", err)
	}
	if tok2 != "" {
		t.Errorf("second Reserve succeeded (token=%q); Cancel-after-Commit released the slot", tok2)
	}
}

// TestFileRepository_CancelDownload_CreditsUncountedBytes verifies the
// probe-budget accounting: cancelling an uncommitted session with bytes
// already served must add those bytes to files.uncounted_bytes.
func TestFileRepository_CancelDownload_CreditsUncountedBytes(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sesuncounted", 1)

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if err := repo.TouchDownloadSession(ctx, file.ID, token, 37); err != nil {
		t.Fatalf("TouchDownloadSession: %v", err)
	}
	if err := repo.CancelDownload(ctx, file.ID, token); err != nil {
		t.Fatalf("CancelDownload: %v", err)
	}

	got, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.UncountedBytes != 37 {
		t.Errorf("uncounted_bytes = %d, want 37", got.UncountedBytes)
	}
	if got.DownloadCount != 0 {
		t.Errorf("download_count = %d, want 0", got.DownloadCount)
	}

	// A second cancel of the same (already-deleted) token must be a
	// harmless no-op — uncounted_bytes must not be double-credited.
	if err := repo.CancelDownload(ctx, file.ID, token); err != nil {
		t.Fatalf("second CancelDownload: %v", err)
	}
	got, _ = repo.GetByID(ctx, file.ID)
	if got.UncountedBytes != 37 {
		t.Errorf("after double-cancel: uncounted_bytes = %d, want still 37", got.UncountedBytes)
	}
}

// TestFileRepository_ReapDownloadSessions_LeaseRenewalPreventsReap — T5.
// A session whose lease is renewed via TouchDownloadSession shortly before a
// reap must survive; the same session, left untouched, would be reaped by the
// same leaseTTL.
func TestFileRepository_ReapDownloadSessions_LeaseRenewalPreventsReap(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "seslease", 1)

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	// Cross a whole-second boundary so the renewed last_seen_at is
	// distinguishable from created_at at SQLite's DATETIME (second)
	// granularity, then renew the lease exactly as the HTTP heartbeat would.
	time.Sleep(1100 * time.Millisecond)
	if err := repo.TouchDownloadSession(ctx, file.ID, token, 512); err != nil {
		t.Fatalf("TouchDownloadSession: %v", err)
	}

	// A 1-second lease TTL would reap the row based on created_at, but the
	// renewed last_seen_at must keep it alive.
	cancelled, _, err := repo.ReapDownloadSessions(ctx, 1*time.Second, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled != 0 {
		t.Errorf("cancelled = %d, want 0 (lease was renewed)", cancelled)
	}

	sess, err := repo.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess == nil {
		t.Fatal("session was reaped despite lease renewal")
	}
	if sess.BytesServed != 512 {
		t.Errorf("BytesServed = %d, want 512", sess.BytesServed)
	}

	// The slot must still be held.
	tok2, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil {
		t.Fatalf("second ReserveDownload: %v", err)
	}
	if tok2 != "" {
		t.Errorf("second Reserve succeeded (token=%q); lease-renewed slot leaked", tok2)
	}
}

// TestFileRepository_ReapDownloadSessions_StalledLeaseThenSlotLost — the
// complement of lease renewal: an uncommitted session that stops renewing
// gets reaped, and a subsequent commit attempt against the same token — with
// the cap already spent by another reader — reports SlotLost rather than
// over-crediting.
func TestFileRepository_ReapDownloadSessions_StalledLeaseThenSlotLost(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sesstalled", 1)

	orphanToken, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || orphanToken == "" {
		t.Fatalf("ReserveDownload (orphan): token=%q err=%v", orphanToken, err)
	}

	// Negative TTL == "reap everything created before now" (same convention
	// as the ADR-012 reservation reaper tests).
	cancelled, _, err := repo.ReapDownloadSessions(ctx, -1*time.Second, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled < 1 {
		t.Fatalf("cancelled = %d, want >= 1", cancelled)
	}

	// Another reader takes the now-free slot for real.
	otherToken, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || otherToken == "" {
		t.Fatalf("ReserveDownload (other): token=%q err=%v", otherToken, err)
	}
	if result, err := repo.CommitDownloadSession(ctx, file.ID, otherToken); err != nil || result != repository.DownloadCommitCredited {
		t.Fatalf("CommitDownloadSession (other): result=%v err=%v", result, err)
	}

	// The orphaned token's late commit must now report SlotLost, not credit.
	result, err := repo.CommitDownloadSession(ctx, file.ID, orphanToken)
	if err != nil {
		t.Fatalf("CommitDownloadSession (orphan, late): %v", err)
	}
	if result != repository.DownloadCommitSlotLost {
		t.Errorf("orphan late-commit result = %v, want SlotLost", result)
	}

	got, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1 (orphan must not over-credit past the cap)", got.DownloadCount)
	}
}

// TestFileRepository_LookupDownloadSession_ExpiredByMaxAge verifies the "no
// oracle" contract at the repository layer: a session older than maxAge is
// reported as absent (nil, nil), not as an error or a stale-but-present row.
func TestFileRepository_LookupDownloadSession_ExpiredByMaxAge(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sesexpired", 1)

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}

	// A 1-nanosecond maxAge is exceeded by the time this call reaches the
	// DB, regardless of how fresh the row actually is.
	sess, err := repo.LookupDownloadSession(ctx, file.ID, token, time.Hour, 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("LookupDownloadSession returned a session past maxAge; want nil (no oracle)")
	}
}

// TestFileRepository_ReapDownloadSessions_CommittedIdleExpiryNoCounterChange
// — an idle, already-committed session is deleted by the reaper as pure
// record cleanup: no counter changes, since the download was already
// credited at commit time.
func TestFileRepository_ReapDownloadSessions_CommittedIdleExpiryNoCounterChange(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sesidle", 1)

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if _, err := repo.CommitDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CommitDownloadSession: %v", err)
	}
	if _, err := repo.CompleteDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CompleteDownloadSession: %v", err)
	}

	before, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID (before): %v", err)
	}

	// Negative idle TTL: "idle past everything created before now" — reaps
	// the committed row immediately via the idle-cutoff branch.
	cancelled, expired, err := repo.ReapDownloadSessions(ctx, time.Hour, -1*time.Second, 24*time.Hour)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled != 0 {
		t.Errorf("cancelled = %d, want 0 (this is the committed/idle path, not the lease path)", cancelled)
	}
	if expired < 1 {
		t.Fatalf("expired = %d, want >= 1", expired)
	}

	after, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID (after): %v", err)
	}
	if after.DownloadCount != before.DownloadCount || after.CompletedDownloads != before.CompletedDownloads {
		t.Errorf("counters changed after idle-expiry reap: before dc=%d completed=%d, after dc=%d completed=%d",
			before.DownloadCount, before.CompletedDownloads, after.DownloadCount, after.CompletedDownloads)
	}

	// The row itself is gone — a resume attempt with this token now finds
	// nothing (falls back to "new download" at the handler layer).
	sess, err := repo.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("session row still present after idle-expiry reap")
	}
}

// TestFileRepository_LookupDownloadSession_RejectsCompleted — bug-hunter
// finding (HIGH, blocking): without this, a committed-and-fully-delivered
// session's token could be replayed indefinitely (bounded only by
// idleTTL/maxAge, up to SessionMaxAge) to redeliver the whole file to anyone
// holding the token. Lookup must treat a completed session exactly like "not
// found".
func TestFileRepository_LookupDownloadSession_RejectsCompleted(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sescompleted", 1)

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if _, err := repo.CommitDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CommitDownloadSession: %v", err)
	}
	if _, err := repo.CompleteDownloadSession(ctx, file.ID, token); err != nil {
		t.Fatalf("CompleteDownloadSession: %v", err)
	}

	sess, err := repo.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess != nil {
		t.Error("LookupDownloadSession resolved a completed session; want nil (no replay oracle)")
	}
}

// TestFileRepository_ReserveSessionBytes_BoundedByLimit — bug-hunter finding
// (HIGH, blocking), part 2: even for a committed-but-not-yet-completed
// session (a large download still streaming, or one paused mid-transfer),
// ReserveSessionBytes must bound the cumulative bytes a replayed token can
// claim to `limit` (~2x the file size), so a token can't be curled forever to
// redeliver the file piecemeal while it's technically still "in flight".
func TestFileRepository_ReserveSessionBytes_BoundedByLimit(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sesreplaybound", 100) // generous cap: isolate the byte bound, not max_downloads

	token, _, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || token == "" {
		t.Fatalf("ReserveDownload: token=%q err=%v", token, err)
	}
	if result, err := repo.CommitDownloadSession(ctx, file.ID, token); err != nil || result != repository.DownloadCommitCredited {
		t.Fatalf("CommitDownloadSession: result=%v err=%v", result, err)
	}
	// Committed but not completed (no CompleteDownloadSession call) — the
	// state a large in-flight download is in while its token gets replayed.

	const rangeLen = 500
	limit := repository.SessionByteLimit(file.FileSize)
	maxGrantable := int(limit / rangeLen)

	grantedCount := 0
	const attempts = 30
	for i := 0; i < attempts; i++ {
		granted, err := repo.ReserveSessionBytes(ctx, file.ID, token, rangeLen, limit)
		if err != nil {
			t.Fatalf("ReserveSessionBytes attempt %d: %v", i, err)
		}
		if granted {
			grantedCount++
		}
	}
	if grantedCount != maxGrantable {
		t.Errorf("grantedCount = %d, want exactly %d (limit=%d, rangeLen=%d, attempts=%d)", grantedCount, maxGrantable, limit, rangeLen, attempts)
	}

	sess, err := repo.LookupDownloadSession(ctx, file.ID, token, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("LookupDownloadSession: %v", err)
	}
	if sess == nil {
		t.Fatal("session not found")
	}
	if sess.BytesReserved > limit {
		t.Errorf("BytesReserved = %d, want <= %d", sess.BytesReserved, limit)
	}
}

// TestFileRepository_ReapDownloadSessions_RefundsPerRowNotAggregate — bug-hunter
// finding (LOW): the abandoned-session refund must be computed per row
// (MAX(0, probe_bytes_granted - bytes_served) per row, then summed), not by
// summing granted and served separately and clamping the aggregate
// difference. A session that over-served relative to its own grant must
// never let its negative "excess" cancel out a refund genuinely owed by a
// different session on the same file.
func TestFileRepository_ReapDownloadSessions_RefundsPerRowNotAggregate(t *testing.T) {
	db := setupTestDB(t)
	repo := NewFileRepository(db)
	ctx := context.Background()
	file := createSessionTestFile(t, repo, "sesreapperrow", 100)
	// fileSize=4096 (createSessionTestFile) => P=256 (ProbeThreshold),
	// budget=1024 — both reserves below fit inside the budget, so each is
	// granted the full P=256.

	tokenA, grantedA, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || tokenA == "" {
		t.Fatalf("ReserveDownload A: token=%q err=%v", tokenA, err)
	}
	if grantedA != 256 {
		t.Fatalf("grantedA = %d, want 256 (test assumes an empty budget)", grantedA)
	}
	// Session A over-serves relative to its own grant.
	if err := repo.TouchDownloadSession(ctx, file.ID, tokenA, 300); err != nil {
		t.Fatalf("TouchDownloadSession A: %v", err)
	}

	tokenB, grantedB, err := repo.ReserveDownload(ctx, file.ID, file.ClaimCode)
	if err != nil || tokenB == "" {
		t.Fatalf("ReserveDownload B: token=%q err=%v", tokenB, err)
	}
	if grantedB != 256 {
		t.Fatalf("grantedB = %d, want 256", grantedB)
	}
	if err := repo.TouchDownloadSession(ctx, file.ID, tokenB, 5); err != nil {
		t.Fatalf("TouchDownloadSession B: %v", err)
	}

	before, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID (before): %v", err)
	}
	if before.UncountedBytes != 512 { // 256 + 256, both charged at Reserve time
		t.Fatalf("uncounted_bytes before reap = %d, want 512", before.UncountedBytes)
	}

	cancelled, _, err := repo.ReapDownloadSessions(ctx, -1*time.Second, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("ReapDownloadSessions: %v", err)
	}
	if cancelled != 2 {
		t.Fatalf("cancelled = %d, want 2", cancelled)
	}

	after, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID (after): %v", err)
	}
	// Per-row refund: A owes max(0, 256-300)=0 (over-served, never negative);
	// B owes max(0, 256-5)=251. Total refund = 251, so uncounted_bytes should
	// drop from 512 to 261. A buggy aggregate computation — (256+256) -
	// (300+5) = 207 clamped (still positive) — would instead leave it at
	// 512-207=305, which this assertion catches.
	if after.UncountedBytes != 261 {
		t.Errorf("uncounted_bytes after reap = %d, want 261 (per-row refund, not aggregate: A over-served so owes 0, B owes 251)", after.UncountedBytes)
	}
}
