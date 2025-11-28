package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// TestCreateFile tests file creation in database
func TestCreateFile(t *testing.T) {
	db := setupTestDB(t)

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

	err := CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	if file.ID == 0 {
		t.Error("CreateFile() did not set file ID")
	}

	// Verify file was inserted
	retrieved, err := GetFileByClaimCode(db, "TEST123")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("GetFileByClaimCode() returned nil")
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

// TestGetFileByClaimCode_NotFound tests retrieving non-existent file
func TestGetFileByClaimCode_NotFound(t *testing.T) {
	db := setupTestDB(t)

	file, err := GetFileByClaimCode(db, "NOTEXIST")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if file != nil {
		t.Error("GetFileByClaimCode() should return nil for non-existent file")
	}
}

// TestGetFileByClaimCode_Expired tests that expired files are treated as not found
func TestGetFileByClaimCode_Expired(t *testing.T) {
	db := setupTestDB(t)

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

	err := CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Attempt to retrieve expired file
	retrieved, err := GetFileByClaimCode(db, "EXPIRED123")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved != nil {
		t.Error("GetFileByClaimCode() should return nil for expired file")
	}
}

// TestIncrementDownloadCount tests download counter increment
func TestIncrementDownloadCount(t *testing.T) {
	db := setupTestDB(t)

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

	err := CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Increment download count
	err = IncrementDownloadCount(db, file.ID)
	if err != nil {
		t.Fatalf("IncrementDownloadCount() error: %v", err)
	}

	// Verify count increased
	retrieved, err := GetFileByClaimCode(db, "DOWNLOAD123")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved.DownloadCount != 1 {
		t.Errorf("DownloadCount = %d, want 1", retrieved.DownloadCount)
	}

	// Increment again
	err = IncrementDownloadCount(db, file.ID)
	if err != nil {
		t.Fatalf("Second IncrementDownloadCount() error: %v", err)
	}

	// Verify count is now 2
	retrieved, err = GetFileByClaimCode(db, "DOWNLOAD123")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved.DownloadCount != 2 {
		t.Errorf("DownloadCount = %d, want 2", retrieved.DownloadCount)
	}
}

// TestIncrementDownloadCount_NotFound tests incrementing non-existent file
func TestIncrementDownloadCount_NotFound(t *testing.T) {
	db := setupTestDB(t)

	err := IncrementDownloadCount(db, 99999)
	if err == nil {
		t.Error("IncrementDownloadCount() should return error for non-existent file")
	}
}

// TestDeleteExpiredFiles tests cleanup of expired files
func TestDeleteExpiredFiles(t *testing.T) {
	db := setupTestDB(t)

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

	err = CreateFile(db, expiredFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
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

	err = CreateFile(db, activeFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Create physical file for active file
	activePath := filepath.Join(tmpDir, activeFile.StoredFilename)
	err = os.WriteFile(activePath, []byte("active content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Delete expired files
	deletedCount, err := DeleteExpiredFiles(db, tmpDir, nil)
	if err != nil {
		t.Fatalf("DeleteExpiredFiles() error: %v", err)
	}

	if deletedCount != 1 {
		t.Errorf("DeleteExpiredFiles() deleted %d files, want 1", deletedCount)
	}

	// Verify expired file is gone from database
	retrieved, err := GetFileByClaimCode(db, "EXPIRED1")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved != nil {
		t.Error("Expired file should be deleted from database")
	}

	// Verify expired physical file is deleted
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Error("Expired physical file should be deleted")
	}

	// Verify active file still exists in database
	retrieved, err = GetFileByClaimCode(db, "ACTIVE1")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved == nil {
		t.Error("Active file should still exist in database")
	}

	// Verify active physical file still exists
	if _, err := os.Stat(activePath); err != nil {
		t.Errorf("Active physical file should still exist: %v", err)
	}
}

// TestDeleteExpiredFiles_FileAlreadyDeleted tests cleanup when physical file is already gone
func TestDeleteExpiredFiles_FileAlreadyDeleted(t *testing.T) {
	db := setupTestDB(t)

	// Create temporary upload directory
	tmpDir, err := os.MkdirTemp("", "test-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create expired file in DB but NOT on disk (expired 2 hours ago to account for 1-hour grace period)
	expiredFile := &models.File{
		ClaimCode:        "EXPIRED_NO_FILE",
		OriginalFilename: "missing.txt",
		StoredFilename:   "stored-missing.txt",
		FileSize:         100,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-2 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, expiredFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Don't create physical file - simulating already deleted file

	// Delete expired files
	deletedCount, err := DeleteExpiredFiles(db, tmpDir, nil)
	if err != nil {
		t.Fatalf("DeleteExpiredFiles() error: %v", err)
	}

	// Should still delete DB record even though file is missing
	if deletedCount != 1 {
		t.Errorf("DeleteExpiredFiles() deleted %d files, want 1", deletedCount)
	}

	// Verify DB record is deleted
	retrieved, err := GetFileByClaimCode(db, "EXPIRED_NO_FILE")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved != nil {
		t.Error("DB record should be deleted even when physical file is missing")
	}
}

// TestDeleteExpiredFiles_FileDeletionFails tests cleanup when file deletion fails
// This test is skipped when running as root since root can delete files regardless of permissions
func TestDeleteExpiredFiles_FileDeletionFails(t *testing.T) {
	// Skip this test if running as root (uid 0)
	if os.Geteuid() == 0 {
		t.Skip("Skipping test when running as root - root can bypass file permissions")
	}

	db := setupTestDB(t)

	// Create temporary upload directory
	tmpDir, err := os.MkdirTemp("", "test-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a subdirectory that we'll make read-only
	readOnlyDir := filepath.Join(tmpDir, "readonly")
	err = os.Mkdir(readOnlyDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create readonly dir: %v", err)
	}

	// Create expired file (expired 2 hours ago to account for 1-hour grace period)
	expiredFile := &models.File{
		ClaimCode:        "EXPIRED_LOCKED",
		OriginalFilename: "locked.txt",
		StoredFilename:   "stored-locked.txt",
		FileSize:         100,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-2 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, expiredFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Create physical file in the readonly subdirectory
	filePath := filepath.Join(readOnlyDir, expiredFile.StoredFilename)
	err = os.WriteFile(filePath, []byte("locked content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Make subdirectory read-only to prevent file deletion
	// Mode 0555 (r-xr-xr-x) allows reading and listing but not modification
	err = os.Chmod(readOnlyDir, 0555)
	if err != nil {
		t.Fatalf("Failed to chmod directory: %v", err)
	}

	// Restore directory permissions after test (even if test fails)
	defer func() {
		os.Chmod(readOnlyDir, 0755)
	}()

	// Call DeleteExpiredFiles with the readonly directory as upload dir
	deletedCount, err := DeleteExpiredFiles(db, readOnlyDir, nil)
	if err != nil {
		t.Fatalf("DeleteExpiredFiles() error: %v", err)
	}

	// Should NOT delete anything because file deletion failed due to permission denied
	if deletedCount != 0 {
		t.Errorf("DeleteExpiredFiles() deleted %d files, want 0 (file deletion should fail)", deletedCount)
	}

	// Verify DB record is KEPT for retry
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE claim_code = ?", "EXPIRED_LOCKED").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query database: %v", err)
	}

	if count != 1 {
		t.Error("DB record should be kept when file deletion fails")
	}

	// Restore permissions to check file existence
	os.Chmod(readOnlyDir, 0755)

	// Verify physical file still exists
	if _, err := os.Stat(filePath); err != nil {
		t.Errorf("Physical file should still exist when deletion fails: %v", err)
	}
}

// TestDeleteExpiredFiles_ValidationFails tests cleanup when filename validation fails
func TestDeleteExpiredFiles_ValidationFails(t *testing.T) {
	db := setupTestDB(t)

	// Create temporary upload directory
	tmpDir, err := os.MkdirTemp("", "test-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create expired file with INVALID stored filename (contains path traversal)
	// Note: We're bypassing CreateFile validation by inserting directly
	query := `
		INSERT INTO files (
			claim_code, original_filename, stored_filename, file_size,
			mime_type, expires_at, uploader_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	// Expired 2 hours ago to account for 1-hour grace period
	expiresAt := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	_, err = db.Exec(query, "INVALID_PATH", "test.txt", "../evil.txt", 100, "text/plain", expiresAt, "192.168.1.1")
	if err != nil {
		t.Fatalf("Failed to insert invalid file: %v", err)
	}

	// Delete expired files
	deletedCount, err := DeleteExpiredFiles(db, tmpDir, nil)
	if err != nil {
		t.Fatalf("DeleteExpiredFiles() error: %v", err)
	}

	// Should NOT delete because validation fails
	if deletedCount != 0 {
		t.Errorf("DeleteExpiredFiles() deleted %d files, want 0 (validation should fail)", deletedCount)
	}

	// Verify DB record is KEPT for investigation
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE claim_code = ?", "INVALID_PATH").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query database: %v", err)
	}

	if count != 1 {
		t.Error("DB record should be kept when validation fails")
	}
}

// TestDeleteExpiredFiles_MultipleFiles tests cleanup of multiple expired files
func TestDeleteExpiredFiles_MultipleFiles(t *testing.T) {
	db := setupTestDB(t)

	// Create temporary upload directory
	tmpDir, err := os.MkdirTemp("", "test-uploads-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create 3 expired files (expired 2 hours ago to account for 1-hour grace period)
	for i := 1; i <= 3; i++ {
		claimCode := "MULTI" + string(rune('0'+i))
		originalFilename := "file" + string(rune('0'+i)) + ".txt"
		storedFilename := "stored-multi" + string(rune('0'+i)) + ".txt"

		file := &models.File{
			ClaimCode:        claimCode,
			OriginalFilename: originalFilename,
			StoredFilename:   storedFilename,
			FileSize:         100 * int64(i),
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(-2 * time.Hour),
			UploaderIP:       "192.168.1.1",
		}

		err = CreateFile(db, file)
		if err != nil {
			t.Fatalf("CreateFile() error: %v", err)
		}

		// Create physical file
		filePath := filepath.Join(tmpDir, file.StoredFilename)
		err = os.WriteFile(filePath, []byte("content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Delete expired files
	deletedCount, err := DeleteExpiredFiles(db, tmpDir, nil)
	if err != nil {
		t.Fatalf("DeleteExpiredFiles() error: %v", err)
	}

	if deletedCount != 3 {
		t.Errorf("DeleteExpiredFiles() deleted %d files, want 3", deletedCount)
	}

	// Verify all files are deleted from database
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE claim_code LIKE 'MULTI%'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query database: %v", err)
	}

	if count != 0 {
		t.Errorf("Found %d files in DB, want 0 (all should be deleted)", count)
	}
}

// TestGetTotalUsage tests total storage calculation
func TestGetTotalUsage(t *testing.T) {
	db := setupTestDB(t)

	// Test with empty database
	usage, err := GetTotalUsage(db)
	if err != nil {
		t.Fatalf("GetTotalUsage() error: %v", err)
	}

	if usage != 0 {
		t.Errorf("GetTotalUsage() = %d, want 0 for empty database", usage)
	}

	// Create active files
	file1 := &models.File{
		ClaimCode:        "FILE1",
		OriginalFilename: "file1.txt",
		StoredFilename:   "stored-file1.txt",
		FileSize:         1000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, file1)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	file2 := &models.File{
		ClaimCode:        "FILE2",
		OriginalFilename: "file2.txt",
		StoredFilename:   "stored-file2.txt",
		FileSize:         2000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, file2)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Create expired file (should not be counted)
	expiredFile := &models.File{
		ClaimCode:        "EXPIRED",
		OriginalFilename: "expired.txt",
		StoredFilename:   "stored-expired.txt",
		FileSize:         5000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, expiredFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Get total usage
	usage, err = GetTotalUsage(db)
	if err != nil {
		t.Fatalf("GetTotalUsage() error: %v", err)
	}

	// Should be 1000 + 2000 = 3000 (expired file not counted)
	expectedUsage := int64(3000)
	if usage != expectedUsage {
		t.Errorf("GetTotalUsage() = %d, want %d", usage, expectedUsage)
	}
}

// TestGetStats tests statistics retrieval
func TestGetStats(t *testing.T) {
	db := setupTestDB(t)

	// Test with empty database
	totalFiles, storageUsed, err := GetStats(db, "")
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}

	if totalFiles != 0 {
		t.Errorf("GetStats() totalFiles = %d, want 0", totalFiles)
	}

	if storageUsed != 0 {
		t.Errorf("GetStats() storageUsed = %d, want 0", storageUsed)
	}

	// Create active files
	file1 := &models.File{
		ClaimCode:        "STAT1",
		OriginalFilename: "stat1.txt",
		StoredFilename:   "stored-stat1.txt",
		FileSize:         500,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, file1)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	file2 := &models.File{
		ClaimCode:        "STAT2",
		OriginalFilename: "stat2.txt",
		StoredFilename:   "stored-stat2.txt",
		FileSize:         1500,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, file2)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Create expired file (should not be counted)
	expiredFile := &models.File{
		ClaimCode:        "STAT_EXPIRED",
		OriginalFilename: "expired.txt",
		StoredFilename:   "stored-expired.txt",
		FileSize:         3000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, expiredFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Get stats
	totalFiles, storageUsed, err = GetStats(db, "")
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}

	// Should count only active files
	if totalFiles != 2 {
		t.Errorf("GetStats() totalFiles = %d, want 2", totalFiles)
	}

	expectedStorage := int64(2000) // 500 + 1500
	if storageUsed != expectedStorage {
		t.Errorf("GetStats() storageUsed = %d, want %d", storageUsed, expectedStorage)
	}
}

// TestCreateFileWithQuotaCheck_Success tests file creation with quota check when under limit
func TestCreateFileWithQuotaCheck_Success(t *testing.T) {
	db := setupTestDB(t)

	// Create a small existing file
	existingFile := &models.File{
		ClaimCode:        "EXISTING1",
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

	// Create new file with quota check (2000 bytes under 10GB limit)
	newFile := &models.File{
		ClaimCode:        "NEWFILE1",
		OriginalFilename: "new.txt",
		StoredFilename:   "stored-new.txt",
		FileSize:         2000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	quotaLimit := int64(10 * 1024 * 1024 * 1024) // 10GB
	err = CreateFileWithQuotaCheck(db, newFile, quotaLimit)
	if err != nil {
		t.Fatalf("CreateFileWithQuotaCheck() error: %v", err)
	}

	// Verify file was created
	retrieved, err := GetFileByClaimCode(db, "NEWFILE1")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("File should be created when under quota")
	}

	if retrieved.FileSize != 2000 {
		t.Errorf("FileSize = %d, want 2000", retrieved.FileSize)
	}
}

// TestCreateFileWithQuotaCheck_ExceedsQuota tests quota enforcement
func TestCreateFileWithQuotaCheck_ExceedsQuota(t *testing.T) {
	db := setupTestDB(t)

	// Create existing file using 900 bytes
	existingFile := &models.File{
		ClaimCode:        "QUOTA1",
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

	// Try to create new file that would exceed quota (900 + 200 > 1000)
	newFile := &models.File{
		ClaimCode:        "QUOTA2",
		OriginalFilename: "exceed.txt",
		StoredFilename:   "stored-exceed.txt",
		FileSize:         200,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	quotaLimit := int64(1000) // 1000 bytes limit
	err = CreateFileWithQuotaCheck(db, newFile, quotaLimit)
	if err == nil {
		t.Fatal("CreateFileWithQuotaCheck() should return error when quota exceeded")
	}

	if !strings.Contains(err.Error(), "quota exceeded") {
		t.Errorf("Expected quota exceeded error, got: %v", err)
	}

	// Verify file was NOT created
	retrieved, err := GetFileByClaimCode(db, "QUOTA2")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved != nil {
		t.Error("File should NOT be created when quota exceeded")
	}
}

// TestCreateFileWithQuotaCheck_IgnoresExpiredFiles tests that expired files don't count toward quota
func TestCreateFileWithQuotaCheck_IgnoresExpiredFiles(t *testing.T) {
	db := setupTestDB(t)

	// Create expired file (should not count toward quota)
	expiredFile := &models.File{
		ClaimCode:        "EXPIRED_QUOTA",
		OriginalFilename: "expired.txt",
		StoredFilename:   "stored-expired.txt",
		FileSize:         5000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err := CreateFile(db, expiredFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Create new file (should succeed because expired file doesn't count)
	newFile := &models.File{
		ClaimCode:        "NEW_QUOTA",
		OriginalFilename: "new.txt",
		StoredFilename:   "stored-new.txt",
		FileSize:         900,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	quotaLimit := int64(1000) // 1000 bytes limit
	err = CreateFileWithQuotaCheck(db, newFile, quotaLimit)
	if err != nil {
		t.Fatalf("CreateFileWithQuotaCheck() should succeed (expired file shouldn't count): %v", err)
	}

	// Verify file was created
	retrieved, err := GetFileByClaimCode(db, "NEW_QUOTA")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("File should be created (expired files don't count toward quota)")
	}
}

// TestCreateFileWithQuotaCheck_ExactlyAtLimit tests file creation exactly at quota limit
func TestCreateFileWithQuotaCheck_ExactlyAtLimit(t *testing.T) {
	db := setupTestDB(t)

	// Create file exactly at limit (should succeed)
	file := &models.File{
		ClaimCode:        "AT_LIMIT",
		OriginalFilename: "exact.txt",
		StoredFilename:   "stored-exact.txt",
		FileSize:         1000,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	quotaLimit := int64(1000)
	err := CreateFileWithQuotaCheck(db, file, quotaLimit)
	if err != nil {
		t.Fatalf("CreateFileWithQuotaCheck() should succeed at exact limit: %v", err)
	}

	// Verify file was created
	retrieved, err := GetFileByClaimCode(db, "AT_LIMIT")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved == nil {
		t.Fatal("File should be created when exactly at quota limit")
	}
}

// TestTryIncrementDownloadWithLimit_Success tests successful download increment
func TestTryIncrementDownloadWithLimit_Success(t *testing.T) {
	db := setupTestDB(t)

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

	err := CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Try to increment (should succeed - 0 < 5)
	success, err := TryIncrementDownloadWithLimit(db, file.ID, "DOWNLOAD_LIMIT1")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit() error: %v", err)
	}

	if !success {
		t.Error("TryIncrementDownloadWithLimit() should succeed when under limit")
	}

	// Verify download count incremented
	retrieved, err := GetFileByClaimCode(db, "DOWNLOAD_LIMIT1")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved.DownloadCount != 1 {
		t.Errorf("DownloadCount = %d, want 1", retrieved.DownloadCount)
	}
}

// TestTryIncrementDownloadWithLimit_ReachesLimit tests hitting download limit
func TestTryIncrementDownloadWithLimit_ReachesLimit(t *testing.T) {
	db := setupTestDB(t)

	maxDownloads := 3
	file := &models.File{
		ClaimCode:        "LIMIT_TEST",
		OriginalFilename: "test.txt",
		StoredFilename:   "stored-test.txt",
		FileSize:         500,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     &maxDownloads,
		DownloadCount:    2, // Already at 2 downloads
		UploaderIP:       "192.168.1.1",
	}

	err := CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Manually set download_count to 2 (CreateFile doesn't set it)
	_, err = db.Exec("UPDATE files SET download_count = 2 WHERE id = ?", file.ID)
	if err != nil {
		t.Fatalf("Failed to set download_count: %v", err)
	}

	// First increment (2 -> 3, should succeed)
	success, err := TryIncrementDownloadWithLimit(db, file.ID, "LIMIT_TEST")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit() error: %v", err)
	}

	if !success {
		t.Error("TryIncrementDownloadWithLimit() should succeed for last allowed download")
	}

	// Verify count is now 3
	retrieved, err := GetFileByClaimCode(db, "LIMIT_TEST")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved.DownloadCount != 3 {
		t.Errorf("DownloadCount = %d, want 3", retrieved.DownloadCount)
	}

	// Try to increment again (3 >= 3, should fail)
	success, err = TryIncrementDownloadWithLimit(db, file.ID, "LIMIT_TEST")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit() error: %v", err)
	}

	if success {
		t.Error("TryIncrementDownloadWithLimit() should fail when limit reached")
	}

	// Verify count stayed at 3
	retrieved, err = GetFileByClaimCode(db, "LIMIT_TEST")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved.DownloadCount != 3 {
		t.Errorf("DownloadCount = %d, want 3 (should not increment past limit)", retrieved.DownloadCount)
	}
}

// TestTryIncrementDownloadWithLimit_NoLimit tests files without download limit
func TestTryIncrementDownloadWithLimit_NoLimit(t *testing.T) {
	db := setupTestDB(t)

	// File with no download limit (MaxDownloads = nil)
	file := &models.File{
		ClaimCode:        "UNLIMITED",
		OriginalFilename: "unlimited.txt",
		StoredFilename:   "stored-unlimited.txt",
		FileSize:         500,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MaxDownloads:     nil, // No limit
		DownloadCount:    100, // Already downloaded 100 times
		UploaderIP:       "192.168.1.1",
	}

	err := CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Manually set download_count to 100 (CreateFile doesn't set it)
	_, err = db.Exec("UPDATE files SET download_count = 100 WHERE id = ?", file.ID)
	if err != nil {
		t.Fatalf("Failed to set download_count: %v", err)
	}

	// Should always succeed when no limit
	success, err := TryIncrementDownloadWithLimit(db, file.ID, "UNLIMITED")
	if err != nil {
		t.Fatalf("TryIncrementDownloadWithLimit() error: %v", err)
	}

	if !success {
		t.Error("TryIncrementDownloadWithLimit() should always succeed when no limit set")
	}

	// Verify count incremented
	retrieved, err := GetFileByClaimCode(db, "UNLIMITED")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved.DownloadCount != 101 {
		t.Errorf("DownloadCount = %d, want 101", retrieved.DownloadCount)
	}
}

// TestTryIncrementDownloadWithLimit_WrongClaimCode tests claim code validation
func TestTryIncrementDownloadWithLimit_WrongClaimCode(t *testing.T) {
	db := setupTestDB(t)

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

	err := CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Try with wrong claim code (should return error)
	success, err := TryIncrementDownloadWithLimit(db, file.ID, "WRONG_CODE")
	if err == nil {
		t.Fatal("TryIncrementDownloadWithLimit() should return error with wrong claim code")
	}

	if success {
		t.Error("TryIncrementDownloadWithLimit() should return success=false with wrong claim code")
	}

	if !strings.Contains(err.Error(), "claim code changed") {
		t.Errorf("Expected 'claim code changed' error, got: %v", err)
	}

	// Verify count NOT incremented
	retrieved, err := GetFileByClaimCode(db, "CORRECT_CODE")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved.DownloadCount != 0 {
		t.Errorf("DownloadCount = %d, want 0 (should not increment with wrong code)", retrieved.DownloadCount)
	}
}

// TestTryIncrementDownloadWithLimit_NonExistentFile tests with non-existent file ID
func TestTryIncrementDownloadWithLimit_NonExistentFile(t *testing.T) {
	db := setupTestDB(t)

	// Try with non-existent file ID (should return error)
	success, err := TryIncrementDownloadWithLimit(db, 99999, "NONEXISTENT")
	if err == nil {
		t.Fatal("TryIncrementDownloadWithLimit() should return error for non-existent file")
	}

	if success {
		t.Error("TryIncrementDownloadWithLimit() should return success=false for non-existent file")
	}

	if !strings.Contains(err.Error(), "claim code changed") {
		t.Errorf("Expected 'claim code changed' error, got: %v", err)
	}
}
