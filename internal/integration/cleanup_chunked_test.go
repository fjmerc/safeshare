package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestChunkedUploadCleanupWorker_DeletesAbandonedUploads tests that the cleanup worker removes abandoned chunked uploads
func TestChunkedUploadCleanupWorker_DeletesAbandonedUploads(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create abandoned partial upload (old last_activity)
	uploadID := uuid.New().String()
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "abandoned.bin",
		TotalSize:    5242880, // 5MB
		ChunkSize:    1048576, // 1MB
		TotalChunks:  5,
		CreatedAt:    time.Now().Add(-48 * time.Hour), // Created 2 days ago
		LastActivity: time.Now().Add(-25 * time.Hour), // Last activity 25 hours ago
		Completed:    false,
	}

	err := repos.PartialUploads.Create(ctx, partialUpload)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Create chunk files on disk
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)

	for i := 0; i < 3; i++ {
		chunkPath := filepath.Join(partialDir, "chunk_"+string(rune('0'+i)))
		os.WriteFile(chunkPath, []byte("test chunk data"), 0644)
	}

	// Run cleanup with 24-hour expiry
	expiryHours := 24
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, expiryHours)
	if err != nil {
		t.Fatalf("CleanupAbandonedUploads() error: %v", err)
	}

	// Should have deleted 1 upload
	if result.DeletedCount != 1 {
		t.Errorf("deleted count = %d, want 1", result.DeletedCount)
	}

	// Verify database record was deleted
	upload, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if err == nil && upload != nil {
		t.Error("abandoned upload should be deleted from database")
	}

	// Verify chunk directory was deleted
	if _, err := os.Stat(partialDir); !os.IsNotExist(err) {
		t.Error("chunk directory should be deleted from filesystem")
	}
}

// TestChunkedUploadCleanupWorker_PreservesActiveUploads tests that active uploads are not deleted
func TestChunkedUploadCleanupWorker_PreservesActiveUploads(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create active partial upload (recent last_activity)
	uploadID := uuid.New().String()
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "active.bin",
		TotalSize:    2097152, // 2MB
		ChunkSize:    1048576, // 1MB
		TotalChunks:  2,
		CreatedAt:    time.Now().Add(-1 * time.Hour),    // Created 1 hour ago
		LastActivity: time.Now().Add(-10 * time.Minute), // Last activity 10 minutes ago
		Completed:    false,
	}

	repos.PartialUploads.Create(ctx, partialUpload)

	// Create chunk files
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)
	os.WriteFile(filepath.Join(partialDir, "chunk_0"), []byte("active chunk"), 0644)

	// Run cleanup with 24-hour expiry
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatalf("CleanupAbandonedUploads() error: %v", err)
	}

	// Should not delete active upload
	if result.DeletedCount != 0 {
		t.Errorf("deleted count = %d, want 0 (active upload should be preserved)", result.DeletedCount)
	}

	// Verify database record still exists
	upload, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if err != nil || upload == nil {
		t.Error("active upload should not be deleted from database")
	}

	// Verify chunk directory still exists
	if _, err := os.Stat(partialDir); os.IsNotExist(err) {
		t.Error("active upload chunk directory should not be deleted")
	}
}

// TestChunkedUploadCleanupWorker_PreservesCompletedUploads tests that completed uploads are not deleted
func TestChunkedUploadCleanupWorker_PreservesCompletedUploads(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create completed partial upload
	uploadID := uuid.New().String()
	claimCode := "claim123"
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "completed.bin",
		TotalSize:    1048576, // 1MB
		ChunkSize:    1048576, // 1MB
		TotalChunks:  1,
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		LastActivity: time.Now().Add(-25 * time.Hour), // Old activity
		Completed:    true,                            // But completed
		ClaimCode:    &claimCode,
	}

	repos.PartialUploads.Create(ctx, partialUpload)

	// Run cleanup
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatalf("CleanupAbandonedUploads() error: %v", err)
	}

	// Should not delete completed upload
	if result.DeletedCount != 0 {
		t.Errorf("deleted count = %d, want 0 (completed upload should be preserved)", result.DeletedCount)
	}

	// Verify database record still exists
	upload, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if err != nil || upload == nil {
		t.Error("completed upload should not be deleted from database")
	}
}

// TestChunkedUploadCleanupWorker_MultipleAbandonedUploads tests cleanup of multiple abandoned uploads
func TestChunkedUploadCleanupWorker_MultipleAbandonedUploads(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create 5 abandoned uploads
	abandonedIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		abandonedIDs[i] = uuid.New().String()
	}

	for _, uploadID := range abandonedIDs {
		partialUpload := &models.PartialUpload{
			UploadID:     uploadID,
			Filename:     uploadID + ".bin",
			TotalSize:    1048576,
			ChunkSize:    524288,
			TotalChunks:  2,
			CreatedAt:    time.Now().Add(-48 * time.Hour),
			LastActivity: time.Now().Add(-30 * time.Hour), // Abandoned
			Completed:    false,
		}
		repos.PartialUploads.Create(ctx, partialUpload)

		// Create chunks
		partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
		os.MkdirAll(partialDir, 0755)
		os.WriteFile(filepath.Join(partialDir, "chunk_0"), []byte("data"), 0644)
	}

	// Run cleanup
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatalf("CleanupAbandonedUploads() error: %v", err)
	}

	// Should delete all 5 abandoned uploads
	if result.DeletedCount != 5 {
		t.Errorf("deleted count = %d, want 5", result.DeletedCount)
	}

	// Verify all were deleted
	for _, uploadID := range abandonedIDs {
		upload, _ := repos.PartialUploads.GetByUploadID(ctx, uploadID)
		if upload != nil {
			t.Errorf("upload %s should be deleted", uploadID)
		}

		partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
		if _, err := os.Stat(partialDir); !os.IsNotExist(err) {
			t.Errorf("chunk directory for %s should be deleted", uploadID)
		}
	}
}

// TestChunkedUploadCleanupWorker_MixedScenario tests cleanup with mix of active, abandoned, and completed uploads
func TestChunkedUploadCleanupWorker_MixedScenario(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create 3 abandoned uploads
	abandonedIDs := make([]string, 3)
	for i := 0; i < 3; i++ {
		uploadID := uuid.New().String()
		abandonedIDs[i] = uploadID
		partialUpload := &models.PartialUpload{
			UploadID:     uploadID,
			Filename:     fmt.Sprintf("abandoned-%d.bin", i),
			TotalSize:    1048576,
			ChunkSize:    524288,
			TotalChunks:  2,
			CreatedAt:    time.Now().Add(-48 * time.Hour),
			LastActivity: time.Now().Add(-30 * time.Hour), // Abandoned
			Completed:    false,
		}
		repos.PartialUploads.Create(ctx, partialUpload)

		partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
		os.MkdirAll(partialDir, 0755)
		os.WriteFile(filepath.Join(partialDir, "chunk_0"), []byte("data"), 0644)
	}

	// Create 2 active uploads
	for i := 0; i < 2; i++ {
		uploadID := uuid.New().String()
		partialUpload := &models.PartialUpload{
			UploadID:     uploadID,
			Filename:     fmt.Sprintf("active-%d.bin", i),
			TotalSize:    1048576,
			ChunkSize:    524288,
			TotalChunks:  2,
			CreatedAt:    time.Now().Add(-1 * time.Hour),
			LastActivity: time.Now().Add(-5 * time.Minute), // Active
			Completed:    false,
		}
		repos.PartialUploads.Create(ctx, partialUpload)

		partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
		os.MkdirAll(partialDir, 0755)
		os.WriteFile(filepath.Join(partialDir, "chunk_0"), []byte("data"), 0644)
	}

	// Create 1 completed upload
	completedUploadID := uuid.New().String()
	claimCode := "claim456"
	completedUpload := &models.PartialUpload{
		UploadID:     completedUploadID,
		Filename:     "completed.bin",
		TotalSize:    1048576,
		ChunkSize:    1048576,
		TotalChunks:  1,
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		LastActivity: time.Now().Add(-30 * time.Hour),
		Completed:    true,
		ClaimCode:    &claimCode,
	}
	repos.PartialUploads.Create(ctx, completedUpload)

	// Run cleanup
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatalf("CleanupAbandonedUploads() error: %v", err)
	}

	// Should delete only the 3 abandoned uploads
	if result.DeletedCount != 3 {
		t.Errorf("deleted count = %d, want 3 (only abandoned uploads)", result.DeletedCount)
	}
}

// TestChunkedUploadCleanupWorker_ChunkDirectoryMissing tests cleanup when chunk directory doesn't exist
func TestChunkedUploadCleanupWorker_ChunkDirectoryMissing(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create abandoned upload without creating chunks on disk
	uploadID := uuid.New().String()
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "nochunks.bin",
		TotalSize:    1048576,
		ChunkSize:    524288,
		TotalChunks:  2,
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		LastActivity: time.Now().Add(-30 * time.Hour),
		Completed:    false,
	}
	repos.PartialUploads.Create(ctx, partialUpload)

	// Don't create chunk directory

	// Run cleanup (should handle missing directory gracefully)
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatalf("CleanupAbandonedUploads() error: %v", err)
	}

	// Should still delete database record
	if result.DeletedCount != 1 {
		t.Errorf("deleted count = %d, want 1", result.DeletedCount)
	}

	// Verify database record was deleted
	upload, _ := repos.PartialUploads.GetByUploadID(ctx, uploadID)
	if upload != nil {
		t.Error("upload should be deleted even without chunk directory")
	}
}

// TestChunkedUploadCleanupWorker_ConfigurableExpiry tests cleanup with different expiry times
func TestChunkedUploadCleanupWorker_ConfigurableExpiry(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create upload that's 10 hours old
	uploadID := uuid.New().String()
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "tenhour.bin",
		TotalSize:    1048576,
		ChunkSize:    1048576,
		TotalChunks:  1,
		CreatedAt:    time.Now().Add(-10 * time.Hour),
		LastActivity: time.Now().Add(-10 * time.Hour),
		Completed:    false,
	}
	repos.PartialUploads.Create(ctx, partialUpload)

	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)
	os.WriteFile(filepath.Join(partialDir, "chunk_0"), []byte("data"), 0644)

	// Test with 24-hour expiry - should NOT delete (10 < 24)
	result, _ := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if result.DeletedCount != 0 {
		t.Errorf("with 24-hour expiry: deleted count = %d, want 0", result.DeletedCount)
	}

	// Test with 6-hour expiry - should delete (10 > 6)
	result, _ = utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 6)
	if result.DeletedCount != 1 {
		t.Errorf("with 6-hour expiry: deleted count = %d, want 1", result.DeletedCount)
	}
}

// TestChunkedUploadCleanupWorker_LogsCleanupActions tests that cleanup actions are logged
func TestChunkedUploadCleanupWorker_LogsCleanupActions(t *testing.T) {
	repos, cfg := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create abandoned upload
	uploadID := uuid.New().String()
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "logged.bin",
		TotalSize:    1048576,
		ChunkSize:    1048576,
		TotalChunks:  1,
		CreatedAt:    time.Now().Add(-48 * time.Hour),
		LastActivity: time.Now().Add(-30 * time.Hour),
		Completed:    false,
	}
	repos.PartialUploads.Create(ctx, partialUpload)

	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)
	os.WriteFile(filepath.Join(partialDir, "chunk_0"), []byte("data"), 0644)

	// Run cleanup (should log the deletion)
	result, err := utils.CleanupAbandonedUploads(repos, cfg.UploadDir, 24)
	if err != nil {
		t.Fatalf("CleanupAbandonedUploads() error: %v", err)
	}

	if result.DeletedCount != 1 {
		t.Errorf("deleted count = %d, want 1", result.DeletedCount)
	}

	// Note: Actual log verification would require capturing slog output
	// This test documents the expected behavior
	t.Log("Cleanup should log: upload_id, filename, total_size, time_since_activity")
}
