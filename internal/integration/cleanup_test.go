package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestCleanupExpiredFiles tests the cleanup worker for expired files
func TestCleanupExpiredFiles(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create 3 expired files and 2 active files
	expiredFiles := []string{}
	activeFiles := []string{}

	for i := 0; i < 3; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		storedFilename := "expired_" + claimCode + ".dat"

		// Create database record (expired)
		database.CreateFile(db, &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   storedFilename,
			OriginalFilename: "file.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(-1 * time.Hour),
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
		database.CreateFile(db, &models.File{
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
	deleted, err := database.DeleteExpiredFiles(db, cfg.UploadDir)
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
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create abandoned partial upload (old and incomplete)
	abandonedUploadID := "abandoned-upload-12345"
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
	database.CreatePartialUpload(db, partialUpload)

	// Create chunks on disk
	partialDir := filepath.Join(cfg.UploadDir, ".partial", abandonedUploadID)
	os.MkdirAll(partialDir, 0755)

	for i := 0; i < 2; i++ {
		chunkPath := filepath.Join(partialDir, "chunk_"+string(rune('0'+i)))
		os.WriteFile(chunkPath, make([]byte, 1024), 0644)
	}

	// Create active partial upload (recent)
	activeUploadID := "active-upload-67890"
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
	database.CreatePartialUpload(db, activeUpload)

	// Create chunks for active upload
	activeDir := filepath.Join(cfg.UploadDir, ".partial", activeUploadID)
	os.MkdirAll(activeDir, 0755)
	chunkPath := filepath.Join(activeDir, "chunk_0")
	os.WriteFile(chunkPath, make([]byte, 1024), 0644)

	// Run cleanup (expiry: 24 hours)
	result, err := utils.CleanupAbandonedUploads(db, cfg.UploadDir, 24)
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
	upload, _ := database.GetPartialUpload(db, abandonedUploadID)
	if upload != nil {
		t.Error("abandoned partial upload should be deleted from database")
	}

	// Verify active upload still exists
	activeUploadCheck, _ := database.GetPartialUpload(db, activeUploadID)
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
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create orphaned chunks (no database record)
	orphanedUploadID := "orphaned-chunks-12345"
	orphanedDir := filepath.Join(cfg.UploadDir, ".partial", orphanedUploadID)
	os.MkdirAll(orphanedDir, 0755)

	// Create 3 chunks
	for i := 0; i < 3; i++ {
		chunkPath := filepath.Join(orphanedDir, "chunk_"+string(rune('0'+i)))
		os.WriteFile(chunkPath, make([]byte, 1024), 0644)
	}

	// Run cleanup (should detect and remove orphaned chunks)
	result, err := utils.CleanupAbandonedUploads(db, cfg.UploadDir, 0)
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
	db := testutil.SetupTestDB(t)
	_ = testutil.SetupTestConfig(t)

	// Create old completed upload (for idempotency cleanup)
	oldUploadID := "old-completed-12345"
	claimCode := "claim123456"
	oldUpload := &models.PartialUpload{
		UploadID:    oldUploadID,
		Filename:    "completed.bin",
		TotalSize:   1024,
		ChunkSize:   1024,
		TotalChunks: 1,
		Completed:   true,
		Status:      "completed",
		ClaimCode:   &claimCode,
		CreatedAt:   time.Now().Add(-3 * time.Hour),
		LastActivity: time.Now().Add(-3 * time.Hour),
	}
	database.CreatePartialUpload(db, oldUpload)

	// Create recent completed upload
	recentUploadID := "recent-completed-67890"
	recentClaimCode := "claim789012"
	recentUpload := &models.PartialUpload{
		UploadID:    recentUploadID,
		Filename:    "recent.bin",
		TotalSize:   2048,
		ChunkSize:   1024,
		TotalChunks: 2,
		Completed:   true,
		Status:      "completed",
		ClaimCode:   &recentClaimCode,
		CreatedAt:   time.Now().Add(-30 * time.Minute),
		LastActivity: time.Now().Add(-30 * time.Minute),
	}
	database.CreatePartialUpload(db, recentUpload)

	// Get old completed uploads (older than 1 hour)
	completed, err := database.GetOldCompletedUploads(db, 1)
	if err != nil {
		t.Fatalf("failed to get old completed uploads: %v", err)
	}

	if len(completed) != 1 {
		t.Errorf("old completed uploads = %d, want 1", len(completed))
	}

	if len(completed) > 0 && completed[0].UploadID != oldUploadID {
		t.Errorf("old upload ID = %s, want %s", completed[0].UploadID, oldUploadID)
	}

	// Delete old completed upload
	database.DeletePartialUpload(db, oldUploadID)

	// Verify old upload is deleted
	upload, _ := database.GetPartialUpload(db, oldUploadID)
	if upload != nil {
		t.Error("old completed upload should be deleted")
	}

	// Verify recent upload still exists
	recentCheck, _ := database.GetPartialUpload(db, recentUploadID)
	if recentCheck == nil {
		t.Error("recent completed upload should still exist")
	}

	t.Log("Cleanup completed uploads test completed successfully")
}

// TestCleanupMissingPhysicalFiles tests cleanup when database records exist but files are missing
func TestCleanupMissingPhysicalFiles(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create database record without physical file
	claimCode, _ := utils.GenerateClaimCode()
	storedFilename := "missing_" + claimCode + ".dat"

	database.CreateFile(db, &models.File{
		ClaimCode:        claimCode,
		StoredFilename:   storedFilename,
		OriginalFilename: "missing.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // Expired
		UploaderIP:       "127.0.0.1",
	})

	// Don't create physical file (simulating missing file)

	// Run cleanup
	deleted, err := database.DeleteExpiredFiles(db, cfg.UploadDir)
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	// Should still delete database record even if physical file is missing
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}

	// Verify database record is deleted
	file, _ := database.GetFileByClaimCode(db, claimCode)
	if file != nil {
		t.Error("database record should be deleted even if physical file is missing")
	}

	t.Log("Cleanup missing physical files test completed successfully")
}

// TestCleanupEmptyPartialDirectory tests cleanup of empty partial upload directory
func TestCleanupEmptyPartialDirectory(t *testing.T) {
	_ = testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create empty partial upload directory
	emptyUploadID := "empty-dir-12345"
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
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create only active files
	for i := 0; i < 3; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		storedFilename := "active_" + claimCode + ".dat"

		database.CreateFile(db, &models.File{
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
	deleted, err := database.DeleteExpiredFiles(db, cfg.UploadDir)
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
	cfg := testutil.SetupTestConfig(t)

	uploadID := "size-test-12345"
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
