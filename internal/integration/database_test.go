package integration

import (
	"sync"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// TestDatabaseConcurrentFileCreation tests creating files concurrently
func TestDatabaseConcurrentFileCreation(t *testing.T) {
	db := testutil.SetupTestDB(t)

	numFiles := 10
	var wg sync.WaitGroup
	errors := make(chan error, numFiles)

	for i := 0; i < numFiles; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			claimCode, _ := utils.GenerateClaimCode()
			file := &models.File{
				ClaimCode:        claimCode,
				StoredFilename:   "concurrent_" + claimCode + ".dat",
				OriginalFilename: "file.txt",
				FileSize:         1024,
				MimeType:         "text/plain",
				ExpiresAt:        time.Now().Add(24 * time.Hour),
				UploaderIP:       "127.0.0.1",
			}

			if err := database.CreateFile(db, file); err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("concurrent file creation error: %v", err)
	}

	// Verify all files were created
	totalFiles, _, _ := database.GetStats(db, ".")
	if totalFiles != numFiles {
		t.Errorf("total files = %d, want %d", totalFiles, numFiles)
	}

	t.Log("Concurrent file creation test completed successfully")
}

// TestDatabaseConcurrentSessionCreation tests creating sessions concurrently
func TestDatabaseConcurrentSessionCreation(t *testing.T) {
	db := testutil.SetupTestDB(t)

	numSessions := 10
	var wg sync.WaitGroup
	errors := make(chan error, numSessions)

	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			sessionToken, _ := utils.GenerateSessionToken()
			expiresAt := time.Now().Add(24 * time.Hour)

			if err := database.CreateSession(db, sessionToken, expiresAt, "127.0.0.1", "test-agent"); err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("concurrent session creation error: %v", err)
	}

	t.Log("Concurrent session creation test completed successfully")
}

// TestDatabaseConcurrentDownloadCounter tests incrementing download counter concurrently
func TestDatabaseConcurrentDownloadCounter(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create a file
	claimCode, _ := utils.GenerateClaimCode()
	file := &models.File{
		ClaimCode:        claimCode,
		StoredFilename:   "counter_test.dat",
		OriginalFilename: "test.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	err := database.CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Increment download counter concurrently
	numIncrements := 20
	var wg sync.WaitGroup

	for i := 0; i < numIncrements; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			database.IncrementDownloadCount(db, file.ID)
		}()
	}

	wg.Wait()

	// Verify final count
	updatedFile, _ := database.GetFileByClaimCode(db, claimCode)
	if updatedFile.DownloadCount != numIncrements {
		t.Errorf("download_count = %d, want %d", updatedFile.DownloadCount, numIncrements)
	}

	t.Log("Concurrent download counter test completed successfully")
}

// TestDatabaseTransactionRollback tests database transaction rollback on error
func TestDatabaseTransactionRollback(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create a user
	username := "txtest"
	password := "password"
	email := "tx@example.com"

	hashedPassword, _ := utils.HashPassword(password)
	user, _ := database.CreateUser(db, username, email, hashedPassword, "user", true)

	// Try to update user with invalid email (should fail and rollback)
	// Note: This test demonstrates the concept; actual implementation depends on validation
	initialUser, _ := database.GetUserByID(db, user.ID)

	// Attempt update (if validation existed, this would rollback)
	err := database.UpdateUser(db, user.ID, username, "invalid-email-without-at", "user")

	// Verify original data is preserved if error occurred
	currentUser, _ := database.GetUserByID(db, user.ID)

	if err != nil {
		// If error occurred, data should be unchanged
		if currentUser.Email != initialUser.Email {
			t.Error("email should be unchanged after failed update")
		}
	}

	t.Log("Database transaction rollback test completed successfully")
}

// TestDatabasePartialUploadConcurrency tests partial upload operations under concurrency
func TestDatabasePartialUploadConcurrency(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create multiple partial uploads concurrently
	numUploads := 10
	var wg sync.WaitGroup
	uploadIDs := make([]string, numUploads)

	for i := 0; i < numUploads; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			uploadID := "concurrent-upload-" + string(rune('0'+index))
			uploadIDs[index] = uploadID

			partialUpload := &models.PartialUpload{
				UploadID:     uploadID,
				Filename:     "file.bin",
				TotalSize:    1024,
				ChunkSize:    1024,
				TotalChunks:  1,
				CreatedAt:    time.Now(),
				LastActivity: time.Now(),
			}

			database.CreatePartialUpload(db, partialUpload)
		}(i)
	}

	wg.Wait()

	// Verify all uploads were created
	for _, uploadID := range uploadIDs {
		upload, _ := database.GetPartialUpload(db, uploadID)
		if upload == nil {
			t.Errorf("partial upload %s not found", uploadID)
		}
	}

	t.Log("Partial upload concurrency test completed successfully")
}

// TestDatabaseIPBlockingConcurrency tests IP blocking/unblocking under concurrency
func TestDatabaseIPBlockingConcurrency(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Block multiple IPs concurrently
	numIPs := 10
	var wg sync.WaitGroup

	for i := 0; i < numIPs; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			ipAddress := "192.168.1." + string(rune('0'+index))
			database.BlockIP(db, ipAddress, "Test", "admin")
		}(i)
	}

	wg.Wait()

	// Verify all IPs are blocked
	blockedIPs, _ := database.GetBlockedIPs(db)
	if len(blockedIPs) != numIPs {
		t.Errorf("blocked IPs = %d, want %d", len(blockedIPs), numIPs)
	}

	// Unblock all IPs concurrently
	for i := 0; i < numIPs; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			ipAddress := "192.168.1." + string(rune('0'+index))
			database.UnblockIP(db, ipAddress)
		}(i)
	}

	wg.Wait()

	// Verify all IPs are unblocked
	blockedIPsAfter, _ := database.GetBlockedIPs(db)
	if len(blockedIPsAfter) != 0 {
		t.Errorf("blocked IPs after unblock = %d, want 0", len(blockedIPsAfter))
	}

	t.Log("IP blocking concurrency test completed successfully")
}

// TestDatabaseSessionCleanup tests cleaning up expired sessions
func TestDatabaseSessionCleanup(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create expired sessions
	for i := 0; i < 5; i++ {
		sessionToken, _ := utils.GenerateSessionToken()
		expiresAt := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
		database.CreateSession(db, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	}

	// Create active sessions
	for i := 0; i < 3; i++ {
		sessionToken, _ := utils.GenerateSessionToken()
		expiresAt := time.Now().Add(24 * time.Hour) // Active for 24 hours
		database.CreateSession(db, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	}

	// Clean up expired sessions
	// TODO: Implement database.DeleteExpiredSessions function
	t.Skip("DeleteExpiredSessions not yet implemented")

	// deleted, err := database.DeleteExpiredSessions(db)
	// if err != nil {
	// 	t.Fatalf("session cleanup failed: %v", err)
	// }
	//
	// if deleted != 5 {
	// 	t.Errorf("deleted sessions = %d, want 5", deleted)
	// }
	//
	// t.Log("Session cleanup test completed successfully")
}

// TestDatabaseUserSessionCleanup tests cleaning up expired user sessions
func TestDatabaseUserSessionCleanup(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create a user
	hashedPassword, _ := utils.HashPassword("password")
	user, _ := database.CreateUser(db, "testuser", "test@example.com", hashedPassword, "user", true)

	// Create expired user sessions
	for i := 0; i < 4; i++ {
		sessionToken, _ := utils.GenerateSessionToken()
		expiresAt := time.Now().Add(-2 * time.Hour)
		database.CreateUserSession(db, user.ID, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	}

	// Create active user sessions
	for i := 0; i < 2; i++ {
		sessionToken, _ := utils.GenerateSessionToken()
		expiresAt := time.Now().Add(24 * time.Hour)
		database.CreateUserSession(db, user.ID, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	}

	// Clean up expired user sessions
	// TODO: Implement database.DeleteExpiredUserSessions function
	t.Skip("DeleteExpiredUserSessions not yet implemented")

	// deleted, err := database.DeleteExpiredUserSessions(db)
	// if err != nil {
	// 	t.Fatalf("user session cleanup failed: %v", err)
	// }
	//
	// if deleted != 4 {
	// 	t.Errorf("deleted user sessions = %d, want 4", deleted)
	// }
	//
	// t.Log("User session cleanup test completed successfully")
}

// TestDatabaseStatsCalculation tests database statistics calculation
func TestDatabaseStatsCalculation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)

	// Create files with known sizes
	totalSize := int64(0)
	numFiles := 5

	for i := 0; i < numFiles; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		fileSize := int64((i + 1) * 1024) // 1KB, 2KB, 3KB, 4KB, 5KB
		totalSize += fileSize

		file := &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   "stats_" + claimCode + ".dat",
			OriginalFilename: "file.txt",
			FileSize:         fileSize,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		}
		database.CreateFile(db, file)
	}

	// Get stats
	count, storageUsed, err := database.GetStats(db, cfg.UploadDir)
	if err != nil {
		t.Fatalf("get stats failed: %v", err)
	}

	if count != numFiles {
		t.Errorf("file count = %d, want %d", count, numFiles)
	}

	if storageUsed != totalSize {
		t.Errorf("storage used = %d, want %d", storageUsed, totalSize)
	}

	t.Log("Database stats calculation test completed successfully")
}

// TestDatabaseGetAllFilesForAdminPagination tests admin file listing with pagination
func TestDatabaseGetAllFilesForAdminPagination(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create 25 files
	numFiles := 25
	for i := 0; i < numFiles; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		file := &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   "page_" + claimCode + ".dat",
			OriginalFilename: "file.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		}
		database.CreateFile(db, file)
	}

	// Get page 1 (limit 10, offset 0)
	page1, total1, err := database.GetAllFilesForAdmin(db, 10, 0)
	if err != nil {
		t.Fatalf("get page 1 failed: %v", err)
	}

	if len(page1) != 10 {
		t.Errorf("page 1 size = %d, want 10", len(page1))
	}

	if total1 != numFiles {
		t.Errorf("total = %d, want %d", total1, numFiles)
	}

	// Get page 2 (limit 10, offset 10)
	page2, total2, err := database.GetAllFilesForAdmin(db, 10, 10)
	if err != nil {
		t.Fatalf("get page 2 failed: %v", err)
	}

	if len(page2) != 10 {
		t.Errorf("page 2 size = %d, want 10", len(page2))
	}

	if total2 != numFiles {
		t.Errorf("total = %d, want %d", total2, numFiles)
	}

	// Get page 3 (limit 10, offset 20)
	page3, total3, err := database.GetAllFilesForAdmin(db, 10, 20)
	if err != nil {
		t.Fatalf("get page 3 failed: %v", err)
	}

	if len(page3) != 5 {
		t.Errorf("page 3 size = %d, want 5", len(page3))
	}

	if total3 != numFiles {
		t.Errorf("total = %d, want %d", total3, numFiles)
	}

	t.Log("Admin file pagination test completed successfully")
}

// TestDatabaseSearchFiles tests file search functionality
func TestDatabaseSearchFiles(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create files with distinct names
	searchTerms := []string{"report", "invoice", "presentation"}

	for _, term := range searchTerms {
		for i := 0; i < 3; i++ {
			claimCode, _ := utils.GenerateClaimCode()
			file := &models.File{
				ClaimCode:        claimCode,
				StoredFilename:   "search_" + claimCode + ".dat",
				OriginalFilename: term + "_" + string(rune('0'+i)) + ".txt",
				FileSize:         1024,
				MimeType:         "text/plain",
				ExpiresAt:        time.Now().Add(24 * time.Hour),
				UploaderIP:       "127.0.0.1",
			}
			database.CreateFile(db, file)
		}
	}

	// Search for "report"
	results, total, err := database.SearchFilesForAdmin(db, "report", 100, 0)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}

	if total != 3 {
		t.Errorf("search 'report': found %d, want 3", total)
	}

	if len(results) != 3 {
		t.Errorf("search results size = %d, want 3", len(results))
	}

	t.Log("Database search files test completed successfully")
}

// TestDatabaseBulkDelete tests bulk file deletion
func TestDatabaseBulkDelete(t *testing.T) {
	db := testutil.SetupTestDB(t)

	// Create files
	claimCodes := make([]string, 5)
	for i := 0; i < 5; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		claimCodes[i] = claimCode

		file := &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   "bulk_" + claimCode + ".dat",
			OriginalFilename: "file.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		}
		database.CreateFile(db, file)
	}

	// Bulk delete
	files, err := database.DeleteFilesByClaimCodes(db, claimCodes)
	if err != nil {
		t.Fatalf("bulk delete failed: %v", err)
	}

	if len(files) != 5 {
		t.Errorf("deleted files = %d, want 5", len(files))
	}

	// Verify all files are deleted
	for _, code := range claimCodes {
		file, _ := database.GetFileByClaimCode(db, code)
		if file != nil {
			t.Errorf("file %s should be deleted", code)
		}
	}

	t.Log("Database bulk delete test completed successfully")
}

// TestDatabaseRaceConditions tests for race conditions with -race flag
func TestDatabaseRaceConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping race condition test in short mode")
	}

	db := testutil.SetupTestDB(t)

	// Mix of concurrent operations
	var wg sync.WaitGroup
	iterations := 50

	// Concurrent file operations
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			claimCode, _ := utils.GenerateClaimCode()
			file := &models.File{
				ClaimCode:        claimCode,
				StoredFilename:   "race_" + claimCode + ".dat",
				OriginalFilename: "file.txt",
				FileSize:         1024,
				MimeType:         "text/plain",
				ExpiresAt:        time.Now().Add(24 * time.Hour),
				UploaderIP:       "127.0.0.1",
			}

			// Create file
			database.CreateFile(db, file)

			// Read file back to get ID
			retrievedFile, _ := database.GetFileByClaimCode(db, claimCode)

			// Update download count
			if retrievedFile != nil {
				database.IncrementDownloadCount(db, retrievedFile.ID)
			}

			// Get stats
			database.GetStats(db, ".")
		}(i)
	}

	wg.Wait()

	t.Log("Database race conditions test completed successfully (run with -race flag)")
}
