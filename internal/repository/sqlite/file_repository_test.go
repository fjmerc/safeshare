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

	maxDownloads := 5
	userID := int64(1)
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

	err := repo.Create(ctx, file)
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
