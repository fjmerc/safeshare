package mock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

func TestNewFileRepository(t *testing.T) {
	repo := NewFileRepository()
	if repo == nil {
		t.Fatal("NewFileRepository returned nil")
	}
	if repo.files == nil {
		t.Error("files map should be initialized")
	}
	if repo.byClaimCode == nil {
		t.Error("byClaimCode map should be initialized")
	}
	if repo.nextID != 1 {
		t.Errorf("nextID should be 1, got %d", repo.nextID)
	}
}

func TestFileRepository_AddFile(t *testing.T) {
	repo := NewFileRepository()

	file := &models.File{
		ClaimCode:        "test-code",
		OriginalFilename: "test.txt",
		FileSize:         1024,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}

	repo.AddFile(file)

	if file.ID == 0 {
		t.Error("file ID should be assigned")
	}

	// Verify file is stored
	files := repo.GetFiles()
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}

	// Verify separate copies are stored (modify original shouldn't affect stored)
	file.OriginalFilename = "modified.txt"
	storedFiles := repo.GetFiles()
	if storedFiles[0].OriginalFilename == "modified.txt" {
		t.Error("stored file should be independent of original")
	}
}

func TestFileRepository_Create(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	file := &models.File{
		ClaimCode:        "create-code",
		OriginalFilename: "create.txt",
		FileSize:         2048,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(ctx, file)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if file.ID == 0 {
		t.Error("file ID should be assigned")
	}

	// Test duplicate claim code
	file2 := &models.File{
		ClaimCode:        "create-code", // Same claim code
		OriginalFilename: "create2.txt",
		FileSize:         1024,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}

	err = repo.Create(ctx, file2)
	if !errors.Is(err, repository.ErrDuplicateKey) {
		t.Errorf("expected ErrDuplicateKey, got %v", err)
	}
}

func TestFileRepository_CreateWithQuotaCheck(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	// Add existing file
	repo.AddFile(&models.File{
		ClaimCode: "existing",
		FileSize:  900,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	// Try to add file that exceeds quota
	file := &models.File{
		ClaimCode: "over-quota",
		FileSize:  200,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.CreateWithQuotaCheck(ctx, file, 1000) // 1000 byte limit
	if !errors.Is(err, repository.ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded, got %v", err)
	}

	// Under quota should work
	file2 := &models.File{
		ClaimCode: "under-quota",
		FileSize:  50,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err = repo.CreateWithQuotaCheck(ctx, file2, 1000)
	if err != nil {
		t.Errorf("expected no error for under quota, got %v", err)
	}
}

func TestFileRepository_GetByID(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	file := &models.File{
		ClaimCode:        "get-by-id",
		OriginalFilename: "test.txt",
		FileSize:         1024,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	repo.AddFile(file)

	// Get existing file
	retrieved, err := repo.GetByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if retrieved.ClaimCode != file.ClaimCode {
		t.Errorf("expected claim code %s, got %s", file.ClaimCode, retrieved.ClaimCode)
	}

	// Get non-existing file
	_, err = repo.GetByID(ctx, 999)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileRepository_GetByClaimCode(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	file := &models.File{
		ClaimCode:        "get-by-claim",
		OriginalFilename: "test.txt",
		FileSize:         1024,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	repo.AddFile(file)

	// Get existing file
	retrieved, err := repo.GetByClaimCode(ctx, "get-by-claim")
	if err != nil {
		t.Fatalf("GetByClaimCode failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected file, got nil")
	}
	if retrieved.OriginalFilename != file.OriginalFilename {
		t.Errorf("expected filename %s, got %s", file.OriginalFilename, retrieved.OriginalFilename)
	}

	// Get non-existing file
	retrieved, err = repo.GetByClaimCode(ctx, "non-existent")
	if err != nil {
		t.Errorf("expected no error for non-existent, got %v", err)
	}
	if retrieved != nil {
		t.Error("expected nil for non-existent claim code")
	}

	// Test expired file
	expiredFile := &models.File{
		ClaimCode:        "expired-claim",
		OriginalFilename: "expired.txt",
		FileSize:         1024,
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // Already expired
	}
	repo.AddFile(expiredFile)

	retrieved, err = repo.GetByClaimCode(ctx, "expired-claim")
	if err != nil {
		t.Errorf("expected no error for expired, got %v", err)
	}
	if retrieved != nil {
		t.Error("expected nil for expired file")
	}
}

func TestFileRepository_IncrementDownloadCount(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	file := &models.File{
		ClaimCode:     "download-test",
		DownloadCount: 0,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	repo.AddFile(file)

	err := repo.IncrementDownloadCount(ctx, file.ID)
	if err != nil {
		t.Fatalf("IncrementDownloadCount failed: %v", err)
	}

	retrieved, _ := repo.GetByID(ctx, file.ID)
	if retrieved.DownloadCount != 1 {
		t.Errorf("expected download count 1, got %d", retrieved.DownloadCount)
	}

	// Non-existent file
	err = repo.IncrementDownloadCount(ctx, 999)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileRepository_TryIncrementDownloadWithLimit(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	maxDownloads := 2
	file := &models.File{
		ClaimCode:     "limit-test",
		DownloadCount: 0,
		MaxDownloads:  &maxDownloads,
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	repo.AddFile(file)

	// First download
	success, err := repo.TryIncrementDownloadWithLimit(ctx, file.ID, "limit-test")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit failed: %v", err)
	}
	if !success {
		t.Error("expected success for first download")
	}

	// Second download
	success, err = repo.TryIncrementDownloadWithLimit(ctx, file.ID, "limit-test")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit failed: %v", err)
	}
	if !success {
		t.Error("expected success for second download")
	}

	// Third download - should fail (limit reached)
	success, err = repo.TryIncrementDownloadWithLimit(ctx, file.ID, "limit-test")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit failed: %v", err)
	}
	if success {
		t.Error("expected failure for third download (limit reached)")
	}
}

func TestFileRepository_Delete(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	file := &models.File{
		ClaimCode: "delete-test",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	repo.AddFile(file)

	err := repo.Delete(ctx, file.ID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify deleted
	_, err = repo.GetByID(ctx, file.ID)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Error("file should be deleted")
	}

	// Delete non-existent
	err = repo.Delete(ctx, 999)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileRepository_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	// Add expired file
	repo.AddFile(&models.File{
		ClaimCode: "expired-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	// Add non-expired file
	repo.AddFile(&models.File{
		ClaimCode: "not-expired",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	var callbacks []string
	count, err := repo.DeleteExpired(ctx, "/tmp", func(claimCode, filename string, fileSize int64, mimeType string, expiresAt time.Time) {
		callbacks = append(callbacks, claimCode)
	})

	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 deleted, got %d", count)
	}

	if len(callbacks) != 1 || callbacks[0] != "expired-1" {
		t.Errorf("callback not called correctly: %v", callbacks)
	}

	// Verify non-expired still exists
	files := repo.GetFiles()
	if len(files) != 1 {
		t.Error("non-expired file should still exist")
	}
}

func TestFileRepository_GetStats(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	// Add files
	repo.AddFile(&models.File{
		ClaimCode: "active-1",
		FileSize:  1000,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	repo.AddFile(&models.File{
		ClaimCode: "active-2",
		FileSize:  2000,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
	repo.AddFile(&models.File{
		ClaimCode: "expired-1",
		FileSize:  500,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	stats, err := repo.GetStats(ctx, "/tmp")
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if stats.TotalFiles != 3 {
		t.Errorf("expected 3 total files, got %d", stats.TotalFiles)
	}
	if stats.ActiveFiles != 2 {
		t.Errorf("expected 2 active files, got %d", stats.ActiveFiles)
	}
	if stats.ExpiredFiles != 1 {
		t.Errorf("expected 1 expired file, got %d", stats.ExpiredFiles)
	}
	if stats.StorageUsed != 3500 {
		t.Errorf("expected 3500 bytes used, got %d", stats.StorageUsed)
	}
}

func TestFileRepository_SearchForAdmin(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	repo.AddFile(&models.File{
		ClaimCode:        "abc123",
		OriginalFilename: "document.pdf",
		UploaderIP:       "192.168.1.1",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	})
	repo.AddFile(&models.File{
		ClaimCode:        "xyz789",
		OriginalFilename: "image.png",
		UploaderIP:       "10.0.0.1",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	})

	// Search by claim code
	results, total, err := repo.SearchForAdmin(ctx, "abc", 10, 0)
	if err != nil {
		t.Fatalf("SearchForAdmin failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 match, got %d", total)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	// Search by filename (case insensitive)
	results, total, err = repo.SearchForAdmin(ctx, "DOCUMENT", 10, 0)
	if err != nil {
		t.Fatalf("SearchForAdmin failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 match for filename, got %d", total)
	}

	// Search by IP
	results, total, err = repo.SearchForAdmin(ctx, "192.168", 10, 0)
	if err != nil {
		t.Fatalf("SearchForAdmin failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 match for IP, got %d", total)
	}
}

func TestFileRepository_ErrorInjection(t *testing.T) {
	ctx := context.Background()
	repo := NewFileRepository()

	testErr := errors.New("test error")

	// Test Create error injection
	repo.CreateError = testErr
	err := repo.Create(ctx, &models.File{ClaimCode: "test"})
	if err != testErr {
		t.Errorf("expected injected error, got %v", err)
	}
	repo.CreateError = nil

	// Test GetByID error injection
	repo.GetByIDError = testErr
	_, err = repo.GetByID(ctx, 1)
	if err != testErr {
		t.Errorf("expected injected error, got %v", err)
	}
	repo.GetByIDError = nil
}

func TestFileRepository_Reset(t *testing.T) {
	repo := NewFileRepository()

	// Add data
	repo.AddFile(&models.File{ClaimCode: "test", ExpiresAt: time.Now().Add(24 * time.Hour)})
	repo.CreateError = errors.New("test")

	// Reset
	repo.Reset()

	// Verify cleared
	if len(repo.GetFiles()) != 0 {
		t.Error("files should be cleared after reset")
	}
	if repo.CreateError != nil {
		t.Error("errors should be cleared after reset")
	}
}

func TestFileRepository_ContextCancellation(t *testing.T) {
	repo := NewFileRepository()
	repo.AddFile(&models.File{ID: 1, ClaimCode: "test", ExpiresAt: time.Now().Add(24 * time.Hour)})

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Operations should return context error
	_, err := repo.GetByID(ctx, 1)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
