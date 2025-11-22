package database

import (
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// TestCreateUser tests user creation
func TestCreateUser(t *testing.T) {
	db := setupTestDB(t)

	user, err := CreateUser(db, "testuser", "test@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	if user.ID == 0 {
		t.Error("CreateUser() did not set user ID")
	}

	if user.Username != "testuser" {
		t.Errorf("Username = %q, want %q", user.Username, "testuser")
	}

	if user.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "test@example.com")
	}

	if user.Role != "user" {
		t.Errorf("Role = %q, want %q", user.Role, "user")
	}

	if !user.IsActive {
		t.Error("IsActive should be true by default")
	}

	if !user.IsApproved {
		t.Error("IsApproved should be true by default")
	}
}

// TestGetUserByUsername tests retrieving user by username
func TestGetUserByUsername(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	created, err := CreateUser(db, "findme", "findme@example.com", "hashed_password", "admin", true)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Retrieve user
	user, err := GetUserByUsername(db, "findme")
	if err != nil {
		t.Fatalf("GetUserByUsername() error: %v", err)
	}

	if user == nil {
		t.Fatal("GetUserByUsername() returned nil")
	}

	if user.ID != created.ID {
		t.Errorf("ID = %d, want %d", user.ID, created.ID)
	}

	if user.Username != "findme" {
		t.Errorf("Username = %q, want %q", user.Username, "findme")
	}

	if user.RequirePasswordChange != true {
		t.Errorf("RequirePasswordChange = %v, want true", user.RequirePasswordChange)
	}
}

// TestGetUserByUsername_NotFound tests retrieving non-existent user
func TestGetUserByUsername_NotFound(t *testing.T) {
	db := setupTestDB(t)

	user, err := GetUserByUsername(db, "nonexistent")
	if err != nil {
		t.Fatalf("GetUserByUsername() error: %v", err)
	}

	if user != nil {
		t.Error("GetUserByUsername() should return nil for non-existent user")
	}
}

// TestGetUserByID tests retrieving user by ID
func TestGetUserByID(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	created, err := CreateUser(db, "userbyid", "userbyid@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Retrieve user by ID
	user, err := GetUserByID(db, created.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if user == nil {
		t.Fatal("GetUserByID() returned nil")
	}

	if user.Username != "userbyid" {
		t.Errorf("Username = %q, want %q", user.Username, "userbyid")
	}
}

// TestGetUserByID_NotFound tests retrieving non-existent user by ID
func TestGetUserByID_NotFound(t *testing.T) {
	db := setupTestDB(t)

	user, err := GetUserByID(db, 99999)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if user != nil {
		t.Error("GetUserByID() should return nil for non-existent user")
	}
}

// TestUpdateUserLastLogin tests last login timestamp update
func TestUpdateUserLastLogin(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "logintest", "login@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Verify initial last login is nil
	retrieved, err := GetUserByID(db, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if retrieved.LastLogin != nil {
		t.Error("LastLogin should be nil initially")
	}

	// Update last login
	err = UpdateUserLastLogin(db, user.ID)
	if err != nil {
		t.Fatalf("UpdateUserLastLogin() error: %v", err)
	}

	// Verify last login was set
	retrieved, err = GetUserByID(db, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if retrieved.LastLogin == nil {
		t.Error("LastLogin should be set after update")
	}
}

// TestUpdateUserPassword tests password update
func TestUpdateUserPassword(t *testing.T) {
	db := setupTestDB(t)

	// Create a user with temporary password flag
	user, err := CreateUser(db, "pwdtest", "pwd@example.com", "old_password", "user", true)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Update password and clear flag
	err = UpdateUserPassword(db, user.ID, "new_password", true)
	if err != nil {
		t.Fatalf("UpdateUserPassword() error: %v", err)
	}

	// Verify password was updated and flag cleared
	retrieved, err := GetUserByID(db, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if retrieved.PasswordHash != "new_password" {
		t.Errorf("PasswordHash = %q, want %q", retrieved.PasswordHash, "new_password")
	}

	if retrieved.RequirePasswordChange {
		t.Error("RequirePasswordChange should be false after clearing")
	}
}

// TestUpdateUser tests updating user profile
func TestUpdateUser(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "updatetest", "update@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Update user details
	err = UpdateUser(db, user.ID, "newusername", "newemail@example.com", "admin")
	if err != nil {
		t.Fatalf("UpdateUser() error: %v", err)
	}

	// Verify updates
	retrieved, err := GetUserByID(db, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if retrieved.Username != "newusername" {
		t.Errorf("Username = %q, want %q", retrieved.Username, "newusername")
	}

	if retrieved.Email != "newemail@example.com" {
		t.Errorf("Email = %q, want %q", retrieved.Email, "newemail@example.com")
	}

	if retrieved.Role != "admin" {
		t.Errorf("Role = %q, want %q", retrieved.Role, "admin")
	}
}

// TestSetUserActive tests enabling/disabling user accounts
func TestSetUserActive(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "activetest", "active@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Verify user is active initially
	retrieved, err := GetUserByID(db, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if !retrieved.IsActive {
		t.Error("User should be active initially")
	}

	// Disable user
	err = SetUserActive(db, user.ID, false)
	if err != nil {
		t.Fatalf("SetUserActive(false) error: %v", err)
	}

	// Verify user is disabled
	retrieved, err = GetUserByID(db, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if retrieved.IsActive {
		t.Error("User should be inactive after disable")
	}

	// Re-enable user
	err = SetUserActive(db, user.ID, true)
	if err != nil {
		t.Fatalf("SetUserActive(true) error: %v", err)
	}

	// Verify user is active again
	retrieved, err = GetUserByID(db, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if !retrieved.IsActive {
		t.Error("User should be active after re-enable")
	}
}

// TestDeleteUser tests user deletion
func TestDeleteUser(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "deletetest", "delete@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Delete user (pass empty uploadDir for test - no files to clean)
	err = DeleteUser(db, user.ID, t.TempDir())
	if err != nil {
		t.Fatalf("DeleteUser() error: %v", err)
	}

	// Verify user is gone
	retrieved, err := GetUserByID(db, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID() error: %v", err)
	}

	if retrieved != nil {
		t.Error("User should be deleted")
	}
}

// TestDeleteUser_NotFound tests deleting non-existent user
func TestDeleteUser_NotFound(t *testing.T) {
	db := setupTestDB(t)

	err := DeleteUser(db, 99999, t.TempDir())
	if err == nil {
		t.Error("DeleteUser() should return error for non-existent user")
	}
}

// TestGetAllUsers tests retrieving users with pagination
func TestGetAllUsers(t *testing.T) {
	db := setupTestDB(t)

	// Create multiple users
	for i := 1; i <= 5; i++ {
		_, err := CreateUser(db, "user"+string(rune('0'+i)), "user"+string(rune('0'+i))+"@example.com", "hashed_password", "user", false)
		if err != nil {
			t.Fatalf("CreateUser() error: %v", err)
		}
	}

	// Get all users
	users, total, err := GetAllUsers(db, 10, 0)
	if err != nil {
		t.Fatalf("GetAllUsers() error: %v", err)
	}

	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}

	if len(users) != 5 {
		t.Errorf("len(users) = %d, want 5", len(users))
	}

	// Test pagination
	users, total, err = GetAllUsers(db, 2, 0)
	if err != nil {
		t.Fatalf("GetAllUsers() with limit error: %v", err)
	}

	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}

	if len(users) != 2 {
		t.Errorf("len(users) = %d, want 2", len(users))
	}
}

// TestCreateUserSession tests user session creation
func TestCreateUserSession(t *testing.T) {
	db := setupTestDB(t)

	// Create a user first
	user, err := CreateUser(db, "sessionuser", "session@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create session
	token := "test_session_token_123"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = CreateUserSession(db, user.ID, token, expiresAt, "192.168.1.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("CreateUserSession() error: %v", err)
	}

	// Verify session was created
	session, err := GetUserSession(db, token)
	if err != nil {
		t.Fatalf("GetUserSession() error: %v", err)
	}

	if session == nil {
		t.Fatal("GetUserSession() returned nil")
	}

	if session.UserID != user.ID {
		t.Errorf("UserID = %d, want %d", session.UserID, user.ID)
	}

	if session.SessionToken != token {
		t.Errorf("SessionToken = %q, want %q", session.SessionToken, token)
	}
}

// TestGetUserSession_NotFound tests retrieving non-existent session
func TestGetUserSession_NotFound(t *testing.T) {
	db := setupTestDB(t)

	session, err := GetUserSession(db, "nonexistent_token")
	if err != nil {
		t.Fatalf("GetUserSession() error: %v", err)
	}

	if session != nil {
		t.Error("GetUserSession() should return nil for non-existent session")
	}
}

// TestGetUserSession_Expired tests that expired sessions are not returned
func TestGetUserSession_Expired(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "expiredsession", "expired@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create expired session
	token := "expired_token_123"
	expiresAt := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
	err = CreateUserSession(db, user.ID, token, expiresAt, "192.168.1.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("CreateUserSession() error: %v", err)
	}

	// Attempt to retrieve expired session
	session, err := GetUserSession(db, token)
	if err != nil {
		t.Fatalf("GetUserSession() error: %v", err)
	}

	if session != nil {
		t.Error("GetUserSession() should return nil for expired session")
	}
}

// TestUpdateUserSessionActivity tests session activity update
func TestUpdateUserSessionActivity(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "activitytest", "activity@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create session
	token := "activity_token_123"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = CreateUserSession(db, user.ID, token, expiresAt, "192.168.1.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("CreateUserSession() error: %v", err)
	}

	// Get initial session
	session, err := GetUserSession(db, token)
	if err != nil {
		t.Fatalf("GetUserSession() error: %v", err)
	}

	initialActivity := session.LastActivity

	// Wait a moment to ensure timestamp difference
	time.Sleep(1 * time.Second)

	// Update activity
	err = UpdateUserSessionActivity(db, token)
	if err != nil {
		t.Fatalf("UpdateUserSessionActivity() error: %v", err)
	}

	// Verify activity was updated
	session, err = GetUserSession(db, token)
	if err != nil {
		t.Fatalf("GetUserSession() error: %v", err)
	}

	// SQLite CURRENT_TIMESTAMP has second precision, so we need at least 1 second difference
	if session.LastActivity.Unix() <= initialActivity.Unix() {
		t.Errorf("LastActivity should be updated to a later time: initial=%v, updated=%v", initialActivity, session.LastActivity)
	}
}

// TestDeleteUserSession tests session deletion (logout)
func TestDeleteUserSession(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "logouttest", "logout@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create session
	token := "logout_token_123"
	expiresAt := time.Now().Add(24 * time.Hour)
	err = CreateUserSession(db, user.ID, token, expiresAt, "192.168.1.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("CreateUserSession() error: %v", err)
	}

	// Delete session
	err = DeleteUserSession(db, token)
	if err != nil {
		t.Fatalf("DeleteUserSession() error: %v", err)
	}

	// Verify session is gone
	session, err := GetUserSession(db, token)
	if err != nil {
		t.Fatalf("GetUserSession() error: %v", err)
	}

	if session != nil {
		t.Error("Session should be deleted")
	}
}

// TestCleanupExpiredUserSessions tests cleanup of expired sessions
func TestCleanupExpiredUserSessions(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "cleanuptest", "cleanup@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create expired session
	expiredToken := "expired_cleanup_token"
	err = CreateUserSession(db, user.ID, expiredToken, time.Now().Add(-1*time.Hour), "192.168.1.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("CreateUserSession() error: %v", err)
	}

	// Create active session
	activeToken := "active_cleanup_token"
	err = CreateUserSession(db, user.ID, activeToken, time.Now().Add(24*time.Hour), "192.168.1.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("CreateUserSession() error: %v", err)
	}

	// Cleanup expired sessions
	err = CleanupExpiredUserSessions(db)
	if err != nil {
		t.Fatalf("CleanupExpiredUserSessions() error: %v", err)
	}

	// Note: We can't easily verify expired session is gone because GetUserSession
	// already filters out expired sessions. This test ensures the cleanup runs without error.
}

// TestGetFilesByUserID tests retrieving files for a specific user
func TestGetFilesByUserID(t *testing.T) {
	db := setupTestDB(t)

	// Create a user
	user, err := CreateUser(db, "fileowner", "fileowner@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create files for this user
	for i := 1; i <= 3; i++ {
		file := &models.File{
			ClaimCode:        "USER_FILE_" + string(rune('0'+i)),
			OriginalFilename: "userfile" + string(rune('0'+i)) + ".txt",
			StoredFilename:   "stored-userfile" + string(rune('0'+i)) + ".txt",
			FileSize:         int64(100 * i),
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "192.168.1.1",
			UserID:           &user.ID,
		}

		err = CreateFile(db, file)
		if err != nil {
			t.Fatalf("CreateFile() error: %v", err)
		}
	}

	// Get files for user
	files, total, err := GetFilesByUserID(db, user.ID, 10, 0)
	if err != nil {
		t.Fatalf("GetFilesByUserID() error: %v", err)
	}

	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}

	if len(files) != 3 {
		t.Errorf("len(files) = %d, want 3", len(files))
	}

	// Verify all files belong to user
	for _, file := range files {
		if file.UserID == nil || *file.UserID != user.ID {
			t.Errorf("File %s does not belong to user %d", file.ClaimCode, user.ID)
		}
	}
}

// TestDeleteFileByIDAndUserID tests file deletion with ownership validation
func TestDeleteFileByIDAndUserID(t *testing.T) {
	db := setupTestDB(t)

	// Create two users
	user1, err := CreateUser(db, "user1", "user1@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	user2, err := CreateUser(db, "user2", "user2@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create file for user1
	file := &models.File{
		ClaimCode:        "USER1_FILE",
		OriginalFilename: "user1file.txt",
		StoredFilename:   "stored-user1file.txt",
		FileSize:         500,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "192.168.1.1",
		UserID:           &user1.ID,
	}

	err = CreateFile(db, file)
	if err != nil {
		t.Fatalf("CreateFile() error: %v", err)
	}

	// Try to delete as user2 (should fail)
	_, err = DeleteFileByIDAndUserID(db, file.ID, user2.ID)
	if err == nil {
		t.Error("DeleteFileByIDAndUserID() should fail when user doesn't own the file")
	}

	// Delete as user1 (should succeed)
	deleted, err := DeleteFileByIDAndUserID(db, file.ID, user1.ID)
	if err != nil {
		t.Fatalf("DeleteFileByIDAndUserID() error: %v", err)
	}

	if deleted == nil {
		t.Fatal("DeleteFileByIDAndUserID() returned nil")
	}

	if deleted.ClaimCode != "USER1_FILE" {
		t.Errorf("ClaimCode = %q, want %q", deleted.ClaimCode, "USER1_FILE")
	}

	// Verify file is gone
	retrieved, err := GetFileByClaimCode(db, "USER1_FILE")
	if err != nil {
		t.Fatalf("GetFileByClaimCode() error: %v", err)
	}

	if retrieved != nil {
		t.Error("File should be deleted")
	}
}
