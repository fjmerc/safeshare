package database

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
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
	if err := RunMigrations(db); err != nil {
		db.Close()
		t.Fatalf("failed to run migrations: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

// TestValidateAdminCredentials_Success tests successful admin credential validation
func TestValidateAdminCredentials_Success(t *testing.T) {
	db := setupTestDB(t)

	// Initialize admin credentials
	err := InitializeAdminCredentials(db, "admin", "password123")
	if err != nil {
		t.Fatalf("failed to initialize admin credentials: %v", err)
	}

	// Validate correct credentials
	valid, err := ValidateAdminCredentials(db, "admin", "password123")
	if err != nil {
		t.Fatalf("failed to validate credentials: %v", err)
	}
	if !valid {
		t.Error("expected valid credentials")
	}
}

// TestValidateAdminCredentials_WrongPassword tests admin credential validation with wrong password
func TestValidateAdminCredentials_WrongPassword(t *testing.T) {
	db := setupTestDB(t)

	// Initialize admin credentials
	err := InitializeAdminCredentials(db, "admin", "password123")
	if err != nil {
		t.Fatalf("failed to initialize admin credentials: %v", err)
	}

	// Validate incorrect credentials
	valid, err := ValidateAdminCredentials(db, "admin", "wrongpassword")
	if err != nil {
		t.Fatalf("failed to validate credentials: %v", err)
	}
	if valid {
		t.Error("expected invalid credentials for wrong password")
	}
}

// TestValidateAdminCredentials_WrongUsername tests admin credential validation with wrong username
func TestValidateAdminCredentials_WrongUsername(t *testing.T) {
	db := setupTestDB(t)

	// Initialize admin credentials
	err := InitializeAdminCredentials(db, "admin", "password123")
	if err != nil {
		t.Fatalf("failed to initialize admin credentials: %v", err)
	}

	// Validate with wrong username
	valid, err := ValidateAdminCredentials(db, "wronguser", "password123")
	if err != nil {
		t.Fatalf("failed to validate credentials: %v", err)
	}
	if valid {
		t.Error("expected invalid credentials for wrong username")
	}
}

// TestInitializeAdminCredentials_CreateNew tests creating new admin credentials
func TestInitializeAdminCredentials_CreateNew(t *testing.T) {
	db := setupTestDB(t)

	err := InitializeAdminCredentials(db, "admin", "password123")
	if err != nil {
		t.Fatalf("failed to initialize admin credentials: %v", err)
	}

	// Verify credentials were created
	var username, passwordHash string
	err = db.QueryRow("SELECT username, password_hash FROM admin_credentials WHERE id = 1").Scan(&username, &passwordHash)
	if err != nil {
		t.Fatalf("failed to query admin credentials: %v", err)
	}

	if username != "admin" {
		t.Errorf("username = %q, want %q", username, "admin")
	}

	// Verify password hash
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("password123"))
	if err != nil {
		t.Error("password hash does not match")
	}
}

// TestInitializeAdminCredentials_Update tests updating existing admin credentials
func TestInitializeAdminCredentials_Update(t *testing.T) {
	db := setupTestDB(t)

	// Create initial credentials
	err := InitializeAdminCredentials(db, "admin", "oldpassword")
	if err != nil {
		t.Fatalf("failed to initialize admin credentials: %v", err)
	}

	// Update credentials
	err = InitializeAdminCredentials(db, "newadmin", "newpassword")
	if err != nil {
		t.Fatalf("failed to update admin credentials: %v", err)
	}

	// Verify credentials were updated
	var username, passwordHash string
	err = db.QueryRow("SELECT username, password_hash FROM admin_credentials WHERE id = 1").Scan(&username, &passwordHash)
	if err != nil {
		t.Fatalf("failed to query admin credentials: %v", err)
	}

	if username != "newadmin" {
		t.Errorf("username = %q, want %q", username, "newadmin")
	}

	// Verify new password hash
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("newpassword"))
	if err != nil {
		t.Error("new password hash does not match")
	}

	// Verify old password doesn't work
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("oldpassword"))
	if err == nil {
		t.Error("old password should not work")
	}
}

// TestCreateSession tests admin session creation
func TestCreateSession(t *testing.T) {
	db := setupTestDB(t)

	token := "test-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)
	ipAddress := "192.168.1.1"
	userAgent := "Mozilla/5.0"

	err := CreateSession(db, token, expiresAt, ipAddress, userAgent)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Verify session was created
	session, err := GetSession(db, token)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to exist")
	}

	if session.SessionToken != token {
		t.Errorf("session token = %q, want %q", session.SessionToken, token)
	}
	if session.IPAddress != ipAddress {
		t.Errorf("ip address = %q, want %q", session.IPAddress, ipAddress)
	}
	if session.UserAgent != userAgent {
		t.Errorf("user agent = %q, want %q", session.UserAgent, userAgent)
	}
}

// TestGetSession_NotFound tests getting non-existent session
func TestGetSession_NotFound(t *testing.T) {
	db := setupTestDB(t)

	session, err := GetSession(db, "non-existent-token")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if session != nil {
		t.Error("expected nil session for non-existent token")
	}
}

// TestGetSession_Expired tests that expired sessions are not returned
func TestGetSession_Expired(t *testing.T) {
	db := setupTestDB(t)

	token := "expired-session-token"
	expiresAt := time.Now().Add(-1 * time.Hour) // expired

	err := CreateSession(db, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Try to get expired session (should return nil)
	session, err := GetSession(db, token)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if session != nil {
		t.Error("expected nil session for expired token")
	}
}

// TestUpdateSessionActivity tests updating session last activity
func TestUpdateSessionActivity(t *testing.T) {
	db := setupTestDB(t)

	token := "test-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)

	err := CreateSession(db, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Get initial session
	session1, err := GetSession(db, token)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	// Wait to ensure timestamp difference (SQLite DATETIME has 1-second precision)
	time.Sleep(1100 * time.Millisecond)

	err = UpdateSessionActivity(db, token)
	if err != nil {
		t.Fatalf("failed to update session activity: %v", err)
	}

	// Get updated session
	session2, err := GetSession(db, token)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}

	// LastActivity should be updated
	if !session2.LastActivity.After(session1.LastActivity) {
		t.Error("expected last activity to be updated")
	}
}

// TestDeleteSession tests session deletion
func TestDeleteSession(t *testing.T) {
	db := setupTestDB(t)

	token := "test-session-token"
	expiresAt := time.Now().Add(24 * time.Hour)

	err := CreateSession(db, token, expiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Delete session
	err = DeleteSession(db, token)
	if err != nil {
		t.Fatalf("failed to delete session: %v", err)
	}

	// Verify session is deleted
	session, err := GetSession(db, token)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if session != nil {
		t.Error("expected session to be deleted")
	}
}

// TestCleanupExpiredSessions tests expired session cleanup
func TestCleanupExpiredSessions(t *testing.T) {
	db := setupTestDB(t)

	// Create expired session
	expiredToken := "expired-session"
	expiredAt := time.Now().Add(-1 * time.Hour)
	err := CreateSession(db, expiredToken, expiredAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create expired session: %v", err)
	}

	// Create valid session
	validToken := "valid-session"
	validExpiresAt := time.Now().Add(24 * time.Hour)
	err = CreateSession(db, validToken, validExpiresAt, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("failed to create valid session: %v", err)
	}

	// Run cleanup
	err = CleanupExpiredSessions(db)
	if err != nil {
		t.Fatalf("failed to cleanup expired sessions: %v", err)
	}

	// Verify expired session is deleted (GetSession returns nil for expired sessions anyway)
	// We need to query directly to verify it's actually deleted from DB
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM admin_sessions WHERE session_token = ?", expiredToken).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count sessions: %v", err)
	}
	if count != 0 {
		t.Error("expected expired session to be deleted")
	}

	// Verify valid session still exists
	session, err := GetSession(db, validToken)
	if err != nil {
		t.Fatalf("failed to get valid session: %v", err)
	}
	if session == nil {
		t.Error("expected valid session to still exist")
	}
}

// TestBlockIP tests IP blocking
func TestBlockIP(t *testing.T) {
	db := setupTestDB(t)

	ipAddress := "192.168.1.100"
	reason := "Suspicious activity"
	blockedBy := "admin"

	err := BlockIP(db, ipAddress, reason, blockedBy)
	if err != nil {
		t.Fatalf("failed to block IP: %v", err)
	}

	// Verify IP is blocked
	blocked, err := IsIPBlocked(db, ipAddress)
	if err != nil {
		t.Fatalf("failed to check if IP is blocked: %v", err)
	}
	if !blocked {
		t.Error("expected IP to be blocked")
	}

	// Verify in blocked list
	blockedIPs, err := GetBlockedIPs(db)
	if err != nil {
		t.Fatalf("failed to get blocked IPs: %v", err)
	}
	if len(blockedIPs) != 1 {
		t.Errorf("expected 1 blocked IP, got %d", len(blockedIPs))
	}
	if blockedIPs[0].IPAddress != ipAddress {
		t.Errorf("IP address = %q, want %q", blockedIPs[0].IPAddress, ipAddress)
	}
	if blockedIPs[0].Reason != reason {
		t.Errorf("reason = %q, want %q", blockedIPs[0].Reason, reason)
	}
	if blockedIPs[0].BlockedBy != blockedBy {
		t.Errorf("blocked by = %q, want %q", blockedIPs[0].BlockedBy, blockedBy)
	}
}

// TestUnblockIP tests IP unblocking
func TestUnblockIP(t *testing.T) {
	db := setupTestDB(t)

	ipAddress := "192.168.1.100"
	err := BlockIP(db, ipAddress, "Test", "admin")
	if err != nil {
		t.Fatalf("failed to block IP: %v", err)
	}

	// Unblock IP
	err = UnblockIP(db, ipAddress)
	if err != nil {
		t.Fatalf("failed to unblock IP: %v", err)
	}

	// Verify IP is unblocked
	blocked, err := IsIPBlocked(db, ipAddress)
	if err != nil {
		t.Fatalf("failed to check if IP is blocked: %v", err)
	}
	if blocked {
		t.Error("expected IP to be unblocked")
	}

	// Verify not in blocked list
	blockedIPs, err := GetBlockedIPs(db)
	if err != nil {
		t.Fatalf("failed to get blocked IPs: %v", err)
	}
	if len(blockedIPs) != 0 {
		t.Errorf("expected 0 blocked IPs, got %d", len(blockedIPs))
	}
}

// TestUnblockIP_NotFound tests unblocking non-existent IP
func TestUnblockIP_NotFound(t *testing.T) {
	db := setupTestDB(t)

	err := UnblockIP(db, "192.168.1.100")
	if err == nil {
		t.Error("expected error when unblocking non-existent IP")
	}
}

// TestIsIPBlocked_NotBlocked tests checking non-blocked IP
func TestIsIPBlocked_NotBlocked(t *testing.T) {
	db := setupTestDB(t)

	blocked, err := IsIPBlocked(db, "192.168.1.100")
	if err != nil {
		t.Fatalf("failed to check if IP is blocked: %v", err)
	}
	if blocked {
		t.Error("expected IP to not be blocked")
	}
}

// TestGetBlockedIPs_Empty tests getting blocked IPs when none exist
func TestGetBlockedIPs_Empty(t *testing.T) {
	db := setupTestDB(t)

	blockedIPs, err := GetBlockedIPs(db)
	if err != nil {
		t.Fatalf("failed to get blocked IPs: %v", err)
	}
	if len(blockedIPs) != 0 {
		t.Errorf("expected 0 blocked IPs, got %d", len(blockedIPs))
	}
}

// TestGetBlockedIPs_Multiple tests getting multiple blocked IPs
func TestGetBlockedIPs_Multiple(t *testing.T) {
	db := setupTestDB(t)

	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}

	for _, ip := range ips {
		err := BlockIP(db, ip, "Test", "admin")
		if err != nil {
			t.Fatalf("failed to block IP %s: %v", ip, err)
		}
	}

	blockedIPs, err := GetBlockedIPs(db)
	if err != nil {
		t.Fatalf("failed to get blocked IPs: %v", err)
	}
	if len(blockedIPs) != 3 {
		t.Errorf("expected 3 blocked IPs, got %d", len(blockedIPs))
	}
}

// TestGetAllFilesForAdmin tests paginated file retrieval with user JOIN
func TestGetAllFilesForAdmin(t *testing.T) {
	db := setupTestDB(t)

	// Create test user
	user, err := CreateUser(db, "testuser", "test@example.com", "password123", "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Insert 5 test files (3 with user, 2 anonymous)
	for i := 1; i <= 5; i++ {
		var uid *int64
		if i <= 3 {
			uid = &user.ID
		}

		_, err := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, created_at, expires_at, uploader_ip, user_id)
			VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'), ?, ?)`,
			fmt.Sprintf("claim%d", i), fmt.Sprintf("file%d.txt", i), fmt.Sprintf("stored%d.bin", i),
			1024*i, "text/plain", "192.168.1.1", uid)
		if err != nil {
			t.Fatalf("failed to insert file %d: %v", i, err)
		}
	}

	// Test pagination - page 1 (limit 2, offset 0)
	files, total, err := GetAllFilesForAdmin(db, 2, 0)
	if err != nil {
		t.Fatalf("failed to get files page 1: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5 files, got %d", total)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files in page 1, got %d", len(files))
	}
	// Verify username is populated for user-uploaded files
	if files[0].Username != nil && *files[0].Username != "testuser" {
		t.Errorf("expected username 'testuser', got %v", *files[0].Username)
	}

	// Test pagination - page 2 (limit 2, offset 2)
	files, total, err = GetAllFilesForAdmin(db, 2, 2)
	if err != nil {
		t.Fatalf("failed to get files page 2: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5 files, got %d", total)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files in page 2, got %d", len(files))
	}

	// Test pagination - page 3 (limit 2, offset 4) - last page
	files, total, err = GetAllFilesForAdmin(db, 2, 4)
	if err != nil {
		t.Fatalf("failed to get files page 3: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5 files, got %d", total)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file in page 3, got %d", len(files))
	}
}

// TestGetAllFilesForAdmin_Empty tests empty file list
func TestGetAllFilesForAdmin_Empty(t *testing.T) {
	db := setupTestDB(t)

	files, total, err := GetAllFilesForAdmin(db, 10, 0)
	if err != nil {
		t.Fatalf("failed to get files: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0 files, got %d", total)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

// TestSearchFilesForAdmin tests file search with various filters
func TestSearchFilesForAdmin(t *testing.T) {
	db := setupTestDB(t)

	// Create test user
	user, err := CreateUser(db, "johndoe", "john@example.com", "password123", "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Insert test files with different attributes
	files := []struct {
		claimCode string
		filename  string
		ip        string
		userID    *int64
	}{
		{"ABC123", "document.pdf", "192.168.1.10", &user.ID},
		{"XYZ789", "image.png", "192.168.1.20", nil},
		{"DEF456", "report.docx", "10.0.0.5", &user.ID},
		{"GHI999", "photo.jpg", "172.16.0.1", nil},
	}

	for _, f := range files {
		_, err := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, created_at, expires_at, uploader_ip, user_id)
			VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'), ?, ?)`,
			f.claimCode, f.filename, "stored.bin", 1024, "application/octet-stream", f.ip, f.userID)
		if err != nil {
			t.Fatalf("failed to insert file %s: %v", f.claimCode, err)
		}
	}

	// Test search by claim code
	results, total, err := SearchFilesForAdmin(db, "ABC", 10, 0)
	if err != nil {
		t.Fatalf("failed to search by claim code: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 result for claim code search, got %d", total)
	}
	if len(results) != 1 || results[0].ClaimCode != "ABC123" {
		t.Errorf("expected ABC123, got %v", results)
	}

	// Test search by filename
	results, total, err = SearchFilesForAdmin(db, "image", 10, 0)
	if err != nil {
		t.Fatalf("failed to search by filename: %v", err)
	}
	if total != 1 {
		t.Errorf("expected 1 result for filename search, got %d", total)
	}
	if len(results) != 1 || results[0].OriginalFilename != "image.png" {
		t.Errorf("expected image.png, got %v", results)
	}

	// Test search by IP address
	results, total, err = SearchFilesForAdmin(db, "192.168.1", 10, 0)
	if err != nil {
		t.Fatalf("failed to search by IP: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 results for IP search, got %d", total)
	}

	// Test search by username (via LEFT JOIN)
	results, total, err = SearchFilesForAdmin(db, "johndoe", 10, 0)
	if err != nil {
		t.Fatalf("failed to search by username: %v", err)
	}
	if total != 2 {
		t.Errorf("expected 2 results for username search, got %d", total)
	}

	// Test search with no results
	results, total, err = SearchFilesForAdmin(db, "NOTFOUND", 10, 0)
	if err != nil {
		t.Fatalf("failed to search with no results: %v", err)
	}
	if total != 0 {
		t.Errorf("expected 0 results for not found search, got %d", total)
	}
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}
}

// TestSearchFilesForAdmin_Pagination tests search result pagination
func TestSearchFilesForAdmin_Pagination(t *testing.T) {
	db := setupTestDB(t)

	// Insert 5 files with similar names
	for i := 1; i <= 5; i++ {
		_, err := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, created_at, expires_at, uploader_ip)
			VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'), ?)`,
			fmt.Sprintf("claim%d", i), fmt.Sprintf("testfile%d.txt", i), "stored.bin", 1024, "text/plain", "192.168.1.1")
		if err != nil {
			t.Fatalf("failed to insert file %d: %v", i, err)
		}
	}

	// Page 1: limit 2, offset 0
	results, total, err := SearchFilesForAdmin(db, "testfile", 2, 0)
	if err != nil {
		t.Fatalf("failed to search page 1: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5 results, got %d", total)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results in page 1, got %d", len(results))
	}

	// Page 2: limit 2, offset 2
	results, total, err = SearchFilesForAdmin(db, "testfile", 2, 2)
	if err != nil {
		t.Fatalf("failed to search page 2: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5 results, got %d", total)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results in page 2, got %d", len(results))
	}
}

// TestDeleteFileByClaimCode tests single file deletion
func TestDeleteFileByClaimCode(t *testing.T) {
	db := setupTestDB(t)

	// Insert test file
	claimCode := "TEST123"
	_, err := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, created_at, expires_at, uploader_ip)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'), ?)`,
		claimCode, "test.txt", "stored123.bin", 1024, "text/plain", "192.168.1.1")
	if err != nil {
		t.Fatalf("failed to insert test file: %v", err)
	}

	// Delete file
	file, err := DeleteFileByClaimCode(db, claimCode)
	if err != nil {
		t.Fatalf("failed to delete file: %v", err)
	}
	if file == nil {
		t.Fatal("expected file to be returned")
	}
	if file.ClaimCode != claimCode {
		t.Errorf("expected claim code %s, got %s", claimCode, file.ClaimCode)
	}
	if file.OriginalFilename != "test.txt" {
		t.Errorf("expected filename test.txt, got %s", file.OriginalFilename)
	}
	if file.StoredFilename != "stored123.bin" {
		t.Errorf("expected stored filename stored123.bin, got %s", file.StoredFilename)
	}

	// Verify file is deleted from database
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE claim_code = ?", claimCode).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count files: %v", err)
	}
	if count != 0 {
		t.Errorf("expected file to be deleted, but count = %d", count)
	}
}

// TestDeleteFileByClaimCode_NotFound tests deleting non-existent file
func TestDeleteFileByClaimCode_NotFound(t *testing.T) {
	db := setupTestDB(t)

	file, err := DeleteFileByClaimCode(db, "NOTFOUND")
	if err == nil {
		t.Error("expected error when deleting non-existent file")
	}
	if file != nil {
		t.Error("expected nil file when not found")
	}
	if err.Error() != "file not found" {
		t.Errorf("expected 'file not found' error, got %v", err)
	}
}

// TestDeleteFilesByClaimCodes tests bulk file deletion
func TestDeleteFilesByClaimCodes(t *testing.T) {
	db := setupTestDB(t)

	// Insert 5 test files
	claimCodes := []string{"BULK1", "BULK2", "BULK3", "BULK4", "BULK5"}
	for i, code := range claimCodes {
		_, err := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, created_at, expires_at, uploader_ip)
			VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'), ?)`,
			code, fmt.Sprintf("file%d.txt", i+1), fmt.Sprintf("stored%d.bin", i+1), 1024*(i+1), "text/plain", "192.168.1.1")
		if err != nil {
			t.Fatalf("failed to insert file %s: %v", code, err)
		}
	}

	// Delete 3 files
	deleteList := []string{"BULK1", "BULK3", "BULK5"}
	files, err := DeleteFilesByClaimCodes(db, deleteList)
	if err != nil {
		t.Fatalf("failed to delete files: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("expected 3 files deleted, got %d", len(files))
	}

	// Verify correct files were deleted
	expectedCodes := map[string]bool{"BULK1": true, "BULK3": true, "BULK5": true}
	for _, file := range files {
		if !expectedCodes[file.ClaimCode] {
			t.Errorf("unexpected file deleted: %s", file.ClaimCode)
		}
	}

	// Verify files are deleted from database
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE claim_code IN ('BULK1', 'BULK3', 'BULK5')").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count deleted files: %v", err)
	}
	if count != 0 {
		t.Errorf("expected deleted files to be gone, but count = %d", count)
	}

	// Verify remaining files still exist
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE claim_code IN ('BULK2', 'BULK4')").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count remaining files: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 remaining files, but count = %d", count)
	}
}

// TestDeleteFilesByClaimCodes_PartialNotFound tests bulk delete with some non-existent files
func TestDeleteFilesByClaimCodes_PartialNotFound(t *testing.T) {
	db := setupTestDB(t)

	// Insert 2 test files
	_, err := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, created_at, expires_at, uploader_ip)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'), ?)`,
		"EXISTS1", "file1.txt", "stored1.bin", 1024, "text/plain", "192.168.1.1")
	if err != nil {
		t.Fatalf("failed to insert file 1: %v", err)
	}
	_, err = db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, created_at, expires_at, uploader_ip)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now', '+24 hours'), ?)`,
		"EXISTS2", "file2.txt", "stored2.bin", 2048, "text/plain", "192.168.1.1")
	if err != nil {
		t.Fatalf("failed to insert file 2: %v", err)
	}

	// Try to delete 4 files (2 exist, 2 don't)
	deleteList := []string{"EXISTS1", "NOTFOUND1", "EXISTS2", "NOTFOUND2"}
	files, err := DeleteFilesByClaimCodes(db, deleteList)
	if err != nil {
		t.Fatalf("failed to delete files: %v", err)
	}
	// Should only delete the 2 that exist (skip non-existent ones)
	if len(files) != 2 {
		t.Errorf("expected 2 files deleted, got %d", len(files))
	}

	// Verify correct files were deleted
	for _, file := range files {
		if file.ClaimCode != "EXISTS1" && file.ClaimCode != "EXISTS2" {
			t.Errorf("unexpected file deleted: %s", file.ClaimCode)
		}
	}
}

// TestDeleteFilesByClaimCodes_EmptyList tests bulk delete with empty list
func TestDeleteFilesByClaimCodes_EmptyList(t *testing.T) {
	db := setupTestDB(t)

	files, err := DeleteFilesByClaimCodes(db, []string{})
	if err == nil {
		t.Error("expected error for empty claim codes list")
	}
	if files != nil {
		t.Error("expected nil files for empty list")
	}
	if err.Error() != "no claim codes provided" {
		t.Errorf("expected 'no claim codes provided' error, got %v", err)
	}
}
