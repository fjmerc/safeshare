package database

import (
	"database/sql"
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

	// Wait a moment and update activity (longer wait to ensure timestamp difference)
	time.Sleep(500 * time.Millisecond)

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
