package database

import (
	"os"
	"path/filepath"
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

	// Create expired file
	expiredFile := &models.File{
		ClaimCode:        "EXPIRED1",
		OriginalFilename: "expired1.txt",
		StoredFilename:   "stored-expired1.txt",
		FileSize:         100,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour),
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
	deletedCount, err := DeleteExpiredFiles(db, tmpDir)
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

	// Create expired file in DB but NOT on disk
	expiredFile := &models.File{
		ClaimCode:        "EXPIRED_NO_FILE",
		OriginalFilename: "missing.txt",
		StoredFilename:   "stored-missing.txt",
		FileSize:         100,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour),
		UploaderIP:       "192.168.1.1",
	}

	err = CreateFile(db, expiredFile)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Don't create physical file - simulating already deleted file

	// Delete expired files
	deletedCount, err := DeleteExpiredFiles(db, tmpDir)
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

	// Create expired file
	expiredFile := &models.File{
		ClaimCode:        "EXPIRED_LOCKED",
		OriginalFilename: "locked.txt",
		StoredFilename:   "stored-locked.txt",
		FileSize:         100,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(-1 * time.Hour),
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
	deletedCount, err := DeleteExpiredFiles(db, readOnlyDir)
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

	expiresAt := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	_, err = db.Exec(query, "INVALID_PATH", "test.txt", "../evil.txt", 100, "text/plain", expiresAt, "192.168.1.1")
	if err != nil {
		t.Fatalf("Failed to insert invalid file: %v", err)
	}

	// Delete expired files
	deletedCount, err := DeleteExpiredFiles(db, tmpDir)
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

	// Create 3 expired files
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
			ExpiresAt:        time.Now().Add(-1 * time.Hour),
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
	deletedCount, err := DeleteExpiredFiles(db, tmpDir)
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
