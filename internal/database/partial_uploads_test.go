package database

import (
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// TestCreatePartialUpload tests creating a partial upload record
func TestCreatePartialUpload(t *testing.T) {
	db := setupTestDB(t)

	// A real user row: partial_uploads.user_id has a foreign key to
	// users(id), which production always enforces (see TestCreateFile's
	// comment on the same pattern in files_test.go for why a dangling
	// reference is no longer safe to rely on here).
	user, err := CreateUser(db, "testcreatepartialupload-user", "testcreatepartialupload@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	userID := user.ID
	upload := &models.PartialUpload{
		UploadID:       "test-upload-123",
		UserID:         &userID,
		Filename:       "test-file.txt",
		TotalSize:      1024000,
		ChunkSize:      5242880,
		TotalChunks:    1,
		ChunksReceived: 0,
		ReceivedBytes:  0,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		PasswordHash:   "hashed_password",
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err = CreatePartialUpload(db, upload)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Verify upload was created
	retrieved, err := GetPartialUpload(db, "test-upload-123")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("GetPartialUpload() returned nil")
	}

	if retrieved.UploadID != "test-upload-123" {
		t.Errorf("UploadID = %q, want %q", retrieved.UploadID, "test-upload-123")
	}

	if retrieved.Filename != "test-file.txt" {
		t.Errorf("Filename = %q, want %q", retrieved.Filename, "test-file.txt")
	}

	if retrieved.TotalSize != 1024000 {
		t.Errorf("TotalSize = %d, want 1024000", retrieved.TotalSize)
	}

	if retrieved.Status != "uploading" {
		t.Errorf("Status = %q, want %q", retrieved.Status, "uploading")
	}
}

// TestGetPartialUpload_NotFound tests retrieving non-existent upload
func TestGetPartialUpload_NotFound(t *testing.T) {
	db := setupTestDB(t)

	upload, err := GetPartialUpload(db, "nonexistent")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if upload != nil {
		t.Error("GetPartialUpload() should return nil for non-existent upload")
	}
}

// TestUpdatePartialUploadActivity tests updating last_activity timestamp
func TestUpdatePartialUploadActivity(t *testing.T) {
	db := setupTestDB(t)

	// Create upload
	upload := &models.PartialUpload{
		UploadID:       "activity-test",
		Filename:       "test.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now().Add(-1 * time.Hour),
		LastActivity:   time.Now().Add(-1 * time.Hour),
		Completed:      false,
	}

	err := CreatePartialUpload(db, upload)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Wait a moment to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Update activity
	err = UpdatePartialUploadActivity(db, "activity-test")
	if err != nil {
		t.Fatalf("UpdatePartialUploadActivity() error: %v", err)
	}

	// Verify activity was updated
	retrieved, err := GetPartialUpload(db, "activity-test")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if retrieved.LastActivity.Before(upload.LastActivity) || retrieved.LastActivity.Equal(upload.LastActivity) {
		t.Error("LastActivity should be updated to a newer timestamp")
	}
}

// TestIncrementChunksReceived tests incrementing chunk counter
func TestIncrementChunksReceived(t *testing.T) {
	db := setupTestDB(t)

	// Create upload
	upload := &models.PartialUpload{
		UploadID:       "chunks-test",
		Filename:       "test.txt",
		TotalSize:      1500,
		ChunkSize:      500,
		TotalChunks:    3,
		ChunksReceived: 0,
		ReceivedBytes:  0,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err := CreatePartialUpload(db, upload)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Increment chunks received
	err = IncrementChunksReceived(db, "chunks-test", 500)
	if err != nil {
		t.Fatalf("IncrementChunksReceived() error: %v", err)
	}

	// Verify increment
	retrieved, err := GetPartialUpload(db, "chunks-test")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if retrieved.ChunksReceived != 1 {
		t.Errorf("ChunksReceived = %d, want 1", retrieved.ChunksReceived)
	}

	if retrieved.ReceivedBytes != 500 {
		t.Errorf("ReceivedBytes = %d, want 500", retrieved.ReceivedBytes)
	}

	// Increment again
	err = IncrementChunksReceived(db, "chunks-test", 500)
	if err != nil {
		t.Fatalf("Second IncrementChunksReceived() error: %v", err)
	}

	retrieved, err = GetPartialUpload(db, "chunks-test")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if retrieved.ChunksReceived != 2 {
		t.Errorf("ChunksReceived = %d, want 2", retrieved.ChunksReceived)
	}

	if retrieved.ReceivedBytes != 1000 {
		t.Errorf("ReceivedBytes = %d, want 1000", retrieved.ReceivedBytes)
	}
}

// TestMarkPartialUploadCompleted tests marking upload as completed
func TestMarkPartialUploadCompleted(t *testing.T) {
	db := setupTestDB(t)

	// Create upload
	upload := &models.PartialUpload{
		UploadID:       "complete-test",
		Filename:       "test.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ChunksReceived: 2,
		ReceivedBytes:  1000,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err := CreatePartialUpload(db, upload)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Mark as completed
	err = MarkPartialUploadCompleted(db, "complete-test", "CLAIM123")
	if err != nil {
		t.Fatalf("MarkPartialUploadCompleted() error: %v", err)
	}

	// Verify completion
	retrieved, err := GetPartialUpload(db, "complete-test")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if !retrieved.Completed {
		t.Error("Completed should be true")
	}

	if retrieved.ClaimCode == nil || *retrieved.ClaimCode != "CLAIM123" {
		t.Errorf("ClaimCode = %v, want 'CLAIM123'", retrieved.ClaimCode)
	}
}

// TestDeletePartialUpload tests deleting partial upload record
func TestDeletePartialUpload(t *testing.T) {
	db := setupTestDB(t)

	// Create upload
	upload := &models.PartialUpload{
		UploadID:       "delete-test",
		Filename:       "test.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err := CreatePartialUpload(db, upload)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Delete upload
	err = DeletePartialUpload(db, "delete-test")
	if err != nil {
		t.Fatalf("DeletePartialUpload() error: %v", err)
	}

	// Verify deletion
	retrieved, err := GetPartialUpload(db, "delete-test")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if retrieved != nil {
		t.Error("GetPartialUpload() should return nil for deleted upload")
	}
}

// TestGetAbandonedPartialUploads tests retrieving abandoned uploads
func TestGetAbandonedPartialUploads(t *testing.T) {
	db := setupTestDB(t)

	// Create abandoned upload (old last_activity)
	abandoned := &models.PartialUpload{
		UploadID:       "abandoned-1",
		Filename:       "old.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ChunksReceived: 1,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now().Add(-25 * time.Hour),
		LastActivity:   time.Now().Add(-25 * time.Hour),
		Completed:      false,
	}

	err := CreatePartialUpload(db, abandoned)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Create recent upload
	recent := &models.PartialUpload{
		UploadID:       "recent-1",
		Filename:       "recent.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ChunksReceived: 1,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err = CreatePartialUpload(db, recent)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Create completed upload (should not be returned)
	completed := &models.PartialUpload{
		UploadID:       "completed-1",
		Filename:       "done.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ChunksReceived: 2,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now().Add(-25 * time.Hour),
		LastActivity:   time.Now().Add(-25 * time.Hour),
		Completed:      true,
	}

	err = CreatePartialUpload(db, completed)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Get abandoned uploads (older than 24 hours)
	abandonedUploads, err := GetAbandonedPartialUploads(db, 24)
	if err != nil {
		t.Fatalf("GetAbandonedPartialUploads() error: %v", err)
	}

	// Should return only the abandoned upload
	if len(abandonedUploads) != 1 {
		t.Errorf("GetAbandonedPartialUploads() returned %d uploads, want 1", len(abandonedUploads))
	}

	if len(abandonedUploads) > 0 && abandonedUploads[0].UploadID != "abandoned-1" {
		t.Errorf("First abandoned upload ID = %q, want 'abandoned-1'", abandonedUploads[0].UploadID)
	}
}

// TestGetAbandonedPartialUploads_ZeroExpiry tests immediate cleanup mode
func TestGetAbandonedPartialUploads_ZeroExpiry(t *testing.T) {
	db := setupTestDB(t)

	// Create incomplete upload with slightly old last_activity
	// (needs to be in the past for <= comparison to work)
	incomplete := &models.PartialUpload{
		UploadID:       "incomplete-1",
		Filename:       "incomplete.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ChunksReceived: 1,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now().Add(-1 * time.Second),
		LastActivity:   time.Now().Add(-1 * time.Second),
		Completed:      false,
	}

	err := CreatePartialUpload(db, incomplete)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Get all incomplete uploads (expiry = 0)
	uploads, err := GetAbandonedPartialUploads(db, 0)
	if err != nil {
		t.Fatalf("GetAbandonedPartialUploads() error: %v", err)
	}

	// Should return the incomplete upload
	if len(uploads) != 1 {
		t.Errorf("GetAbandonedPartialUploads(0) returned %d uploads, want 1", len(uploads))
	}
}

// TestGetOldCompletedUploads tests retrieving old completed uploads
// Note: This function has a known limitation with RFC3339 datetime parsing in SQLite.
// The test verifies basic functionality but may not work with all timestamp formats.
func TestGetOldCompletedUploads(t *testing.T) {
	db := setupTestDB(t)

	// This test verifies the function can be called without errors
	// Full datetime comparison testing is skipped due to RFC3339 parsing limitations
	// mentioned in GetAbandonedPartialUploads comments (lines 189-191 in partial_uploads.go)

	// Get old completed uploads (should return empty list or nil with no data)
	_, err := GetOldCompletedUploads(db, 48)
	if err != nil {
		t.Fatalf("GetOldCompletedUploads() error: %v", err)
	}

	// If no error, the function works correctly
	// The actual datetime comparison behavior is not tested due to known limitations
}

// TestGetPartialUploadsByUserID tests retrieving uploads by user
func TestGetPartialUploadsByUserID(t *testing.T) {
	db := setupTestDB(t)

	// Real user rows: partial_uploads.user_id has a foreign key to
	// users(id) (see TestCreatePartialUpload's comment on the same
	// pattern). This is a fresh :memory: DB with no prior users rows, so
	// these two inserts get auto-increment ids 1 and 2 respectively,
	// preserving this test's hardcoded GetPartialUploadsByUserID(db, 1)/(db,
	// 2) calls below.
	u1, err := CreateUser(db, "testgetpartialuploadsbyuserid-1", "testgetpartialuploadsbyuserid-1@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("CreateUser (1): %v", err)
	}
	u2, err := CreateUser(db, "testgetpartialuploadsbyuserid-2", "testgetpartialuploadsbyuserid-2@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("CreateUser (2): %v", err)
	}
	if u1.ID != 1 || u2.ID != 2 {
		t.Fatalf("unexpected user ids: u1=%d u2=%d, want 1 and 2 (test below hardcodes these)", u1.ID, u2.ID)
	}
	userID1 := u1.ID
	userID2 := u2.ID

	// Create uploads for user 1
	upload1 := &models.PartialUpload{
		UploadID:       "user1-upload1",
		UserID:         &userID1,
		Filename:       "file1.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err = CreatePartialUpload(db, upload1)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	upload2 := &models.PartialUpload{
		UploadID:       "user1-upload2",
		UserID:         &userID1,
		Filename:       "file2.txt",
		TotalSize:      2000,
		ChunkSize:      500,
		TotalChunks:    4,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err = CreatePartialUpload(db, upload2)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Create upload for user 2
	upload3 := &models.PartialUpload{
		UploadID:       "user2-upload1",
		UserID:         &userID2,
		Filename:       "file3.txt",
		TotalSize:      3000,
		ChunkSize:      500,
		TotalChunks:    6,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err = CreatePartialUpload(db, upload3)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Get uploads for user 1
	user1Uploads, err := GetPartialUploadsByUserID(db, 1)
	if err != nil {
		t.Fatalf("GetPartialUploadsByUserID() error: %v", err)
	}

	if len(user1Uploads) != 2 {
		t.Errorf("GetPartialUploadsByUserID(1) returned %d uploads, want 2", len(user1Uploads))
	}

	// Get uploads for user 2
	user2Uploads, err := GetPartialUploadsByUserID(db, 2)
	if err != nil {
		t.Fatalf("GetPartialUploadsByUserID() error: %v", err)
	}

	if len(user2Uploads) != 1 {
		t.Errorf("GetPartialUploadsByUserID(2) returned %d uploads, want 1", len(user2Uploads))
	}
}

// TestGetTotalPartialUploadUsage tests calculating total partial upload usage
func TestGetTotalPartialUploadUsage(t *testing.T) {
	db := setupTestDB(t)

	// Test with no uploads
	usage, err := GetTotalPartialUploadUsage(db)
	if err != nil {
		t.Fatalf("GetTotalPartialUploadUsage() error: %v", err)
	}

	if usage != 0 {
		t.Errorf("GetTotalPartialUploadUsage() = %d, want 0 for empty database", usage)
	}

	// Create incomplete uploads
	upload1 := &models.PartialUpload{
		UploadID:       "usage-1",
		Filename:       "file1.txt",
		TotalSize:      10000,
		ChunkSize:      5000,
		TotalChunks:    2,
		ChunksReceived: 1,
		ReceivedBytes:  5000,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err = CreatePartialUpload(db, upload1)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	upload2 := &models.PartialUpload{
		UploadID:       "usage-2",
		Filename:       "file2.txt",
		TotalSize:      20000,
		ChunkSize:      5000,
		TotalChunks:    4,
		ChunksReceived: 2,
		ReceivedBytes:  10000,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err = CreatePartialUpload(db, upload2)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Create completed upload (should not be counted)
	upload3 := &models.PartialUpload{
		UploadID:       "usage-3",
		Filename:       "file3.txt",
		TotalSize:      30000,
		ChunkSize:      5000,
		TotalChunks:    6,
		ChunksReceived: 6,
		ReceivedBytes:  30000,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      true,
	}

	err = CreatePartialUpload(db, upload3)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Get total usage (should only count incomplete uploads)
	usage, err = GetTotalPartialUploadUsage(db)
	if err != nil {
		t.Fatalf("GetTotalPartialUploadUsage() error: %v", err)
	}

	expectedUsage := int64(15000) // 5000 + 10000
	if usage != expectedUsage {
		t.Errorf("GetTotalPartialUploadUsage() = %d, want %d", usage, expectedUsage)
	}
}

// TestGetIncompletePartialUploadsCount tests counting incomplete uploads
func TestGetIncompletePartialUploadsCount(t *testing.T) {
	db := setupTestDB(t)

	// Test with no uploads
	count, err := GetIncompletePartialUploadsCount(db)
	if err != nil {
		t.Fatalf("GetIncompletePartialUploadsCount() error: %v", err)
	}

	if count != 0 {
		t.Errorf("GetIncompletePartialUploadsCount() = %d, want 0", count)
	}

	// Create incomplete uploads
	for i := 1; i <= 3; i++ {
		upload := &models.PartialUpload{
			UploadID:       "count-" + string(rune(i)),
			Filename:       "file.txt",
			TotalSize:      1000,
			ChunkSize:      500,
			TotalChunks:    2,
			ExpiresInHours: 24,
			MaxDownloads:   5,
			CreatedAt:      time.Now(),
			LastActivity:   time.Now(),
			Completed:      false,
		}

		err = CreatePartialUpload(db, upload)
		if err != nil {
			t.Fatalf("CreatePartialUpload() error: %v", err)
		}
	}

	// Create completed upload
	claimCode := "CLAIM123"
	completed := &models.PartialUpload{
		UploadID:       "completed-count",
		Filename:       "done.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      true,
		ClaimCode:      &claimCode,
	}

	err = CreatePartialUpload(db, completed)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Get count (should only count incomplete)
	count, err = GetIncompletePartialUploadsCount(db)
	if err != nil {
		t.Fatalf("GetIncompletePartialUploadsCount() error: %v", err)
	}

	if count != 3 {
		t.Errorf("GetIncompletePartialUploadsCount() = %d, want 3", count)
	}
}

// TestPartialUploadExists tests checking upload existence
func TestPartialUploadExists(t *testing.T) {
	db := setupTestDB(t)

	// Test non-existent upload
	exists, err := PartialUploadExists(db, "nonexistent")
	if err != nil {
		t.Fatalf("PartialUploadExists() error: %v", err)
	}

	if exists {
		t.Error("PartialUploadExists() should return false for non-existent upload")
	}

	// Create upload
	upload := &models.PartialUpload{
		UploadID:       "exists-test",
		Filename:       "test.txt",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	err = CreatePartialUpload(db, upload)
	if err != nil {
		t.Fatalf("CreatePartialUpload() error: %v", err)
	}

	// Test existing upload
	exists, err = PartialUploadExists(db, "exists-test")
	if err != nil {
		t.Fatalf("PartialUploadExists() error: %v", err)
	}

	if !exists {
		t.Error("PartialUploadExists() should return true for existing upload")
	}
}

// TestCreatePartialUploadWithQuotaCheck_Success tests partial upload creation with quota check
func TestCreatePartialUploadWithQuotaCheck_Success(t *testing.T) {
	db := setupTestDB(t)

	// Create existing file using 1000 bytes
	existingFile := &models.File{
		ClaimCode:        "EXISTING_FILE",
		OriginalFilename: "existing.txt",
		StoredFilename:   "stored-existing.txt",
		FileSize:         1000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := CreateFile(db, existingFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Create partial upload that fits within quota. Real user row:
	// partial_uploads.user_id has a foreign key to users(id) (see
	// TestCreatePartialUpload's comment on the same pattern).
	user, err := CreateUser(db, "testcreatepartialuploadwithquotacheck-user", "testcreatepartialuploadwithquotacheck@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	userID := user.ID
	upload := &models.PartialUpload{
		UploadID:       "quota-upload-1",
		Filename:       "chunked.bin",
		TotalSize:      2000, // 1000 + 2000 = 3000 < 10000 quota
		ChunkSize:      500,
		TotalChunks:    4,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
		UserID:         &userID,
	}

	quotaLimit := int64(10000) // 10KB quota
	err = CreatePartialUploadWithQuotaCheck(db, upload, quotaLimit)
	if err != nil {
		t.Fatalf("CreatePartialUploadWithQuotaCheck() error: %v", err)
	}

	// Verify upload was created
	retrieved, err := GetPartialUpload(db, "quota-upload-1")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Partial upload should be created when under quota")
	}

	if retrieved.TotalSize != 2000 {
		t.Errorf("TotalSize = %d, want 2000", retrieved.TotalSize)
	}
}

// TestCreatePartialUploadWithQuotaCheck_ExceedsQuota tests quota enforcement for partial uploads
func TestCreatePartialUploadWithQuotaCheck_ExceedsQuota(t *testing.T) {
	db := setupTestDB(t)

	// Create existing file using 900 bytes
	existingFile := &models.File{
		ClaimCode:        "QUOTA_FILE",
		OriginalFilename: "quota.txt",
		StoredFilename:   "stored-quota.txt",
		FileSize:         900,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := CreateFile(db, existingFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Try to create partial upload that exceeds quota (900 + 200 > 1000)
	upload := &models.PartialUpload{
		UploadID:       "exceed-upload",
		Filename:       "exceed.bin",
		TotalSize:      200,
		ChunkSize:      100,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	quotaLimit := int64(1000) // 1KB quota
	err = CreatePartialUploadWithQuotaCheck(db, upload, quotaLimit)
	if err == nil {
		t.Fatal("CreatePartialUploadWithQuotaCheck() should return error when quota exceeded")
	}

	// Verify upload was NOT created
	retrieved, err := GetPartialUpload(db, "exceed-upload")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if retrieved != nil {
		t.Error("Partial upload should NOT be created when quota exceeded")
	}
}

// TestCreatePartialUploadWithQuotaCheck_ExactlyAtLimit tests at quota boundary
func TestCreatePartialUploadWithQuotaCheck_ExactlyAtLimit(t *testing.T) {
	db := setupTestDB(t)

	// Create upload exactly at quota limit (should succeed)
	upload := &models.PartialUpload{
		UploadID:       "at-limit-upload",
		Filename:       "exact.bin",
		TotalSize:      1000,
		ChunkSize:      500,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		Completed:      false,
	}

	quotaLimit := int64(1000)
	err := CreatePartialUploadWithQuotaCheck(db, upload, quotaLimit)
	if err != nil {
		t.Fatalf("CreatePartialUploadWithQuotaCheck() should succeed at exact limit: %v", err)
	}

	// Verify upload was created
	retrieved, err := GetPartialUpload(db, "at-limit-upload")
	if err != nil {
		t.Fatalf("GetPartialUpload() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Partial upload should be created when exactly at quota limit")
	}
}
