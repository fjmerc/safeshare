package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestCleanupExpiredFiles tests the cleanup worker for expired files
func TestCleanupExpiredFiles(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create 3 expired files and 2 active files
	expiredFiles := []string{}
	activeFiles := []string{}

	for i := 0; i < 3; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		storedFilename := "expired_" + claimCode + ".dat"

		// Create database record (expired 2 hours ago to account for 1-hour grace period)
		repos.Files.Create(ctx, &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   storedFilename,
			OriginalFilename: "file.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(-2 * time.Hour),
			UploaderIP:       "127.0.0.1",
		})

		// Create physical file
		filePath := filepath.Join(cfg.UploadDir, storedFilename)
		os.WriteFile(filePath, []byte("expired"), 0644)

		expiredFiles = append(expiredFiles, storedFilename)
	}

	for i := 0; i < 2; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		storedFilename := "active_" + claimCode + ".dat"

		// Create database record (not expired)
		repos.Files.Create(ctx, &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   storedFilename,
			OriginalFilename: "file.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		})

		// Create physical file
		filePath := filepath.Join(cfg.UploadDir, storedFilename)
		os.WriteFile(filePath, []byte("active"), 0644)

		activeFiles = append(activeFiles, storedFilename)
	}

	// Run cleanup
	deleted, err := repos.Files.DeleteExpired(ctx, cfg.UploadDir, nil)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}

	// Verify expired files are deleted from filesystem
	for _, filename := range expiredFiles {
		filePath := filepath.Join(cfg.UploadDir, filename)
		if _, err := os.Stat(filePath); !os.IsNotExist(err) {
			t.Errorf("expired file should be deleted: %s", filename)
		}
	}

	// Verify active files still exist
	for _, filename := range activeFiles {
		filePath := filepath.Join(cfg.UploadDir, filename)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("active file should still exist: %s", filename)
		}
	}

	t.Log("Cleanup expired files test completed successfully")
}

// TestCleanupAbandonedPartialUploads tests cleanup of abandoned chunked uploads
func TestCleanupAbandonedPartialUploads(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create abandoned partial upload (old and incomplete)
	abandonedUploadID := uuid.New().String()
	partialUpload := &models.PartialUpload{
		UploadID:     abandonedUploadID,
		Filename:     "abandoned.bin",
		TotalSize:    3072,
		ChunkSize:    1024,
		TotalChunks:  3,
		Completed:    false,
		Status:       "uploading",
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		LastActivity: time.Now().Add(-48 * time.Hour),
	}
	repos.PartialUploads.Create(ctx, partialUpload)

	// Create chunks on disk
	partialDir := filepath.Join(cfg.UploadDir, ".partial", abandonedUploadID)
	os.MkdirAll(partialDir, 0755)

	for i := 0; i < 2; i++ {
		chunkPath := filepath.Join(partialDir, "chunk_"+string(rune('0'+i)))
		os.WriteFile(chunkPath, make([]byte, 1024), 0644)
	}

	// Create active partial upload (recent)
	activeUploadID := uuid.New().String()
	activeUpload := &models.PartialUpload{
		UploadID:     activeUploadID,
		Filename:     "active.bin",
		TotalSize:    2048,
		ChunkSize:    1024,
		TotalChunks:  2,
		Completed:    false,
		Status:       "uploading",
		CreatedAt:    time.Now().Add(-1 * time.Hour),
		LastActivity: time.Now().Add(-30 * time.Minute),
	}
	repos.PartialUploads.Create(ctx, activeUpload)

	// Create chunks for active upload
	activeDir := filepath.Join(cfg.UploadDir, ".partial", activeUploadID)
	os.MkdirAll(activeDir, 0755)
	chunkPath := filepath.Join(activeDir, "chunk_0")
	os.WriteFile(chunkPath, make([]byte, 1024), 0644)

	// Run cleanup (expiry: 24 hours)
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	// Verify abandoned upload was cleaned up
	if result.AbandonedCount != 1 {
		t.Errorf("abandoned_count = %d, want 1", result.AbandonedCount)
	}

	if result.BytesReclaimed < 2048 {
		t.Errorf("bytes_reclaimed = %d, want >= 2048", result.BytesReclaimed)
	}

	// Verify abandoned chunks are deleted
	if _, err := os.Stat(partialDir); !os.IsNotExist(err) {
		t.Error("abandoned chunk directory should be deleted")
	}

	// Verify abandoned partial upload is deleted from database
	upload, _ := repos.PartialUploads.GetByUploadID(ctx, abandonedUploadID)
	if upload != nil {
		t.Error("abandoned partial upload should be deleted from database")
	}

	// Verify active upload still exists
	activeUploadCheck, _ := repos.PartialUploads.GetByUploadID(ctx, activeUploadID)
	if activeUploadCheck == nil {
		t.Error("active partial upload should still exist")
	}

	if _, err := os.Stat(activeDir); os.IsNotExist(err) {
		t.Error("active chunk directory should still exist")
	}

	t.Log("Cleanup abandoned partial uploads test completed successfully")
}

// TestCleanupOrphanedChunks tests cleanup of orphaned chunk directories
func TestCleanupOrphanedChunks(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	// Create orphaned chunks (no database record)
	orphanedUploadID := uuid.New().String()
	orphanedDir := filepath.Join(cfg.UploadDir, ".partial", orphanedUploadID)
	os.MkdirAll(orphanedDir, 0755)

	// Create 3 chunks
	for i := 0; i < 3; i++ {
		chunkPath := filepath.Join(orphanedDir, "chunk_"+string(rune('0'+i)))
		os.WriteFile(chunkPath, make([]byte, 1024), 0644)
	}

	// Run cleanup (should detect and remove orphaned chunks)
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 0)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	if result.OrphanedCount != 1 {
		t.Errorf("orphaned_count = %d, want 1", result.OrphanedCount)
	}

	if result.OrphanedBytes < 3072 {
		t.Errorf("orphaned_bytes = %d, want >= 3072", result.OrphanedBytes)
	}

	// Verify orphaned directory is deleted
	if _, err := os.Stat(orphanedDir); !os.IsNotExist(err) {
		t.Error("orphaned chunk directory should be deleted")
	}

	t.Log("Cleanup orphaned chunks test completed successfully")
}

// TestCleanupCompletedUploads tests cleanup of old completed uploads
func TestCleanupCompletedUploads(t *testing.T) {
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create old completed upload (for idempotency cleanup)
	oldUploadID := uuid.New().String()
	claimCode := "claim123456"
	oldUpload := &models.PartialUpload{
		UploadID:     oldUploadID,
		Filename:     "completed.bin",
		TotalSize:    1024,
		ChunkSize:    1024,
		TotalChunks:  1,
		Completed:    true,
		Status:       "completed",
		ClaimCode:    &claimCode,
		CreatedAt:    time.Now().Add(-3 * time.Hour),
		LastActivity: time.Now().Add(-3 * time.Hour),
	}
	repos.PartialUploads.Create(ctx, oldUpload)

	// Create recent completed upload
	recentUploadID := uuid.New().String()
	recentClaimCode := "claim789012"
	recentUpload := &models.PartialUpload{
		UploadID:     recentUploadID,
		Filename:     "recent.bin",
		TotalSize:    2048,
		ChunkSize:    1024,
		TotalChunks:  2,
		Completed:    true,
		Status:       "completed",
		ClaimCode:    &recentClaimCode,
		CreatedAt:    time.Now().Add(-30 * time.Minute),
		LastActivity: time.Now().Add(-30 * time.Minute),
	}
	repos.PartialUploads.Create(ctx, recentUpload)

	// Get old completed uploads (older than 1 hour)
	completed, err := repos.PartialUploads.GetOldCompleted(ctx, 1)
	if err != nil {
		t.Fatalf("failed to get old completed uploads: %v", err)
	}

	// GetOldCompleted should find uploads older than the specified retention period
	// The query uses datetime(last_activity) to properly compare RFC3339 timestamps
	if len(completed) != 1 {
		t.Errorf("old completed uploads = %d, want 1", len(completed))
	}

	if len(completed) > 0 && completed[0].UploadID != oldUploadID {
		t.Errorf("old upload ID = %s, want %s", completed[0].UploadID, oldUploadID)
	}

	// Delete old completed upload
	repos.PartialUploads.Delete(ctx, oldUploadID)

	// Verify old upload is deleted
	upload, _ := repos.PartialUploads.GetByUploadID(ctx, oldUploadID)
	if upload != nil {
		t.Error("old completed upload should be deleted")
	}

	// Verify recent upload still exists
	recentCheck, _ := repos.PartialUploads.GetByUploadID(ctx, recentUploadID)
	if recentCheck == nil {
		t.Error("recent completed upload should still exist")
	}

	t.Log("Cleanup completed uploads test completed successfully")
}

// TestCleanupMissingPhysicalFiles tests cleanup when database records exist but files are missing
func TestCleanupMissingPhysicalFiles(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create database record without physical file
	claimCode, _ := utils.GenerateClaimCode()
	storedFilename := "missing_" + claimCode + ".dat"

	repos.Files.Create(ctx, &models.File{
		ClaimCode:        claimCode,
		StoredFilename:   storedFilename,
		OriginalFilename: "missing.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-2 * time.Hour), // Expired 2 hours ago for 1-hour grace period
		UploaderIP:       "127.0.0.1",
	})

	// Don't create physical file (simulating missing file)

	// Run cleanup
	deleted, err := repos.Files.DeleteExpired(ctx, cfg.UploadDir, nil)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	// Should still delete database record even if physical file is missing
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}

	// Verify database record is deleted
	file, _ := repos.Files.GetByClaimCode(ctx, claimCode)
	if file != nil {
		t.Error("database record should be deleted even if physical file is missing")
	}

	t.Log("Cleanup missing physical files test completed successfully")
}

// TestCleanupEmptyPartialDirectory tests cleanup of empty partial upload directory
func TestCleanupEmptyPartialDirectory(t *testing.T) {
	_, cfg := testutil.SetupTestRepos(t)

	// Create empty partial upload directory
	emptyUploadID := uuid.New().String()
	emptyDir := filepath.Join(cfg.UploadDir, ".partial", emptyUploadID)
	os.MkdirAll(emptyDir, 0755)

	// Verify directory exists
	if _, err := os.Stat(emptyDir); os.IsNotExist(err) {
		t.Fatal("empty directory should exist before cleanup")
	}

	// Run cleanup
	err := utils.CleanupPartialUploadsDir(cfg.UploadDir)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	// Verify empty directory is removed
	if _, err := os.Stat(emptyDir); !os.IsNotExist(err) {
		t.Error("empty directory should be removed")
	}

	t.Log("Cleanup empty partial directory test completed successfully")
}

// TestCleanupNoExpiredFiles tests cleanup when there are no expired files
func TestCleanupNoExpiredFiles(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create only active files
	for i := 0; i < 3; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		storedFilename := "active_" + claimCode + ".dat"

		repos.Files.Create(ctx, &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   storedFilename,
			OriginalFilename: "file.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour), // Not expired
			UploaderIP:       "127.0.0.1",
		})

		filePath := filepath.Join(cfg.UploadDir, storedFilename)
		os.WriteFile(filePath, []byte("active"), 0644)
	}

	// Run cleanup
	deleted, err := repos.Files.DeleteExpired(ctx, cfg.UploadDir, nil)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	// No files should be deleted
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}

	t.Log("Cleanup no expired files test completed successfully")
}

// TestPartialUploadSizeCalculation tests calculating size of partial upload chunks
func TestPartialUploadSizeCalculation(t *testing.T) {
	_, cfg := testutil.SetupTestRepos(t)

	uploadID := uuid.New().String()
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)

	// Create 3 chunks of different sizes
	chunkSizes := []int{1024, 2048, 512}
	totalSize := 0

	for i, size := range chunkSizes {
		chunkPath := filepath.Join(partialDir, "chunk_"+string(rune('0'+i)))
		os.WriteFile(chunkPath, make([]byte, size), 0644)
		totalSize += size
	}

	// Calculate size
	calculatedSize, err := utils.GetUploadChunksSize(cfg.UploadDir, uploadID)
	if err != nil {
		t.Fatalf("size calculation failed: %v", err)
	}

	if calculatedSize != int64(totalSize) {
		t.Errorf("calculated size = %d, want %d", calculatedSize, totalSize)
	}

	// Cleanup
	utils.DeleteChunks(cfg.UploadDir, uploadID)

	t.Log("Partial upload size calculation test completed successfully")
}

// TestCleanupOrphanedFiles tests cleanup of files without database records
func TestCleanupOrphanedFiles(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create a file WITH database record
	trackedCode, _ := utils.GenerateClaimCode()
	trackedFilename := "tracked-" + trackedCode + ".bin"
	repos.Files.Create(ctx, &models.File{
		ClaimCode:        trackedCode,
		StoredFilename:   trackedFilename,
		OriginalFilename: "tracked.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	})
	trackedPath := filepath.Join(cfg.UploadDir, trackedFilename)
	os.WriteFile(trackedPath, []byte("tracked file"), 0644)

	// Create orphaned files (no database record, older than grace period)
	orphanedFilenames := []string{"orphan-1.bin", "orphan-2.bin"}
	for _, filename := range orphanedFilenames {
		orphanPath := filepath.Join(cfg.UploadDir, filename)
		os.WriteFile(orphanPath, []byte("orphaned file"), 0644)
		// Set modification time to 2 hours ago (beyond 1-hour grace period)
		oldTime := time.Now().Add(-2 * time.Hour)
		os.Chtimes(orphanPath, oldTime, oldTime)
	}

	// Create an orphaned file within grace period (should NOT be deleted)
	recentOrphanPath := filepath.Join(cfg.UploadDir, "recent-orphan.bin")
	os.WriteFile(recentOrphanPath, []byte("recent orphan"), 0644)
	// Don't modify time - it's recent

	// Run cleanup with 1-hour grace period
	deleted, bytesReclaimed, err := utils.CleanupOrphanedFiles(repos, cfg.UploadDir, 1)
	if err != nil {
		t.Fatalf("CleanupOrphanedFiles() error: %v", err)
	}

	// Should delete 2 orphaned files (not the recent one)
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	if bytesReclaimed != int64(len("orphaned file")*2) {
		t.Errorf("bytesReclaimed = %d, want %d", bytesReclaimed, len("orphaned file")*2)
	}

	// Verify tracked file still exists
	if _, err := os.Stat(trackedPath); os.IsNotExist(err) {
		t.Error("Tracked file should NOT be deleted")
	}

	// Verify old orphaned files are deleted
	for _, filename := range orphanedFilenames {
		orphanPath := filepath.Join(cfg.UploadDir, filename)
		if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
			t.Errorf("Orphaned file should be deleted: %s", filename)
		}
	}

	// Verify recent orphan still exists (within grace period)
	if _, err := os.Stat(recentOrphanPath); os.IsNotExist(err) {
		t.Error("Recent orphan should NOT be deleted (within grace period)")
	}

	t.Log("Cleanup orphaned files test completed successfully")
}

// TestCleanupOrphanedFiles_NoOrphans tests when there are no orphaned files
func TestCleanupOrphanedFiles_NoOrphans(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create only files WITH database records
	for i := 0; i < 3; i++ {
		code, _ := utils.GenerateClaimCode()
		filename := "tracked-" + code + ".bin"
		repos.Files.Create(ctx, &models.File{
			ClaimCode:        code,
			StoredFilename:   filename,
			OriginalFilename: "test.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		})
		filePath := filepath.Join(cfg.UploadDir, filename)
		os.WriteFile(filePath, []byte("tracked"), 0644)
	}

	// Run cleanup
	deleted, bytesReclaimed, err := utils.CleanupOrphanedFiles(repos, cfg.UploadDir, 1)
	if err != nil {
		t.Fatalf("CleanupOrphanedFiles() error: %v", err)
	}

	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}

	if bytesReclaimed != 0 {
		t.Errorf("bytesReclaimed = %d, want 0", bytesReclaimed)
	}

	t.Log("Cleanup no orphans test completed successfully")
}

// TestCleanupOrphanedFiles_EmptyDirectory tests with empty uploads directory
func TestCleanupOrphanedFiles_EmptyDirectory(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)

	// Ensure directory is empty (just .partial)
	// Run cleanup
	deleted, bytesReclaimed, err := utils.CleanupOrphanedFiles(repos, cfg.UploadDir, 1)
	if err != nil {
		t.Fatalf("CleanupOrphanedFiles() error: %v", err)
	}

	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}

	if bytesReclaimed != 0 {
		t.Errorf("bytesReclaimed = %d, want 0", bytesReclaimed)
	}

	t.Log("Cleanup empty directory test completed successfully")
}
