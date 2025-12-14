package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/fjmerc/safeshare/internal/repository"
)

// setupUserTestDB creates a test database with required schema
func setupUserTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:?_txlock=immediate&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			is_approved INTEGER NOT NULL DEFAULT 1,
			is_active INTEGER NOT NULL DEFAULT 1,
			require_password_change INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			last_login TEXT
		)
	`)
	if err != nil {
		t.Fatalf("failed to create users table: %v", err)
	}

	// Create user_sessions table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS user_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			session_token TEXT UNIQUE NOT NULL,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			expires_at TEXT NOT NULL,
			last_activity TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			ip_address TEXT,
			user_agent TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		t.Fatalf("failed to create user_sessions table: %v", err)
	}

	// Create files table for user file operations
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			claim_code TEXT UNIQUE NOT NULL,
			original_filename TEXT NOT NULL,
			stored_filename TEXT NOT NULL,
			file_size INTEGER NOT NULL,
			mime_type TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
			expires_at TEXT NOT NULL,
			max_downloads INTEGER,
			download_count INTEGER NOT NULL DEFAULT 0,
			completed_downloads INTEGER NOT NULL DEFAULT 0,
			uploader_ip TEXT,
			password_hash TEXT,
			user_id INTEGER,
			sha256_hash TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		)
	`)
	if err != nil {
		t.Fatalf("failed to create files table: %v", err)
	}

	return db
}

func TestUserRepository_Create(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if user.ID == 0 {
		t.Error("expected user ID to be set")
	}
	if user.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %q", user.Username)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %q", user.Email)
	}
	if user.Role != "user" {
		t.Errorf("expected role 'user', got %q", user.Role)
	}
	if !user.IsActive {
		t.Error("expected user to be active")
	}
}

func TestUserRepository_Create_InvalidRole(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	_, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "superadmin", false)
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestUserRepository_Create_InvalidUsername(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Empty username
	_, err := repo.Create(ctx, "", "test@example.com", "hashedpassword", "user", false)
	if err == nil {
		t.Fatal("expected error for empty username")
	}

	// Username too long (over 64 chars)
	longUsername := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, err = repo.Create(ctx, longUsername, "test@example.com", "hashedpassword", "user", false)
	if err == nil {
		t.Fatal("expected error for username too long")
	}
}

func TestUserRepository_Create_InvalidEmail(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Empty email
	_, err := repo.Create(ctx, "testuser", "", "hashedpassword", "user", false)
	if err == nil {
		t.Fatal("expected error for empty email")
	}
}

func TestUserRepository_GetByID(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user first
	created, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Retrieve by ID
	user, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.Username != "testuser" {
		t.Errorf("expected username 'testuser', got %q", user.Username)
	}
}

func TestUserRepository_GetByID_NotFound(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	user, err := repo.GetByID(ctx, 99999)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if user != nil {
		t.Error("expected nil for non-existent user")
	}
}

func TestUserRepository_GetByUsername(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user first
	_, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Retrieve by username
	user, err := repo.GetByUsername(ctx, "testuser")
	if err != nil {
		t.Fatalf("GetByUsername failed: %v", err)
	}
	if user == nil {
		t.Fatal("expected user, got nil")
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %q", user.Email)
	}
}

func TestUserRepository_GetByUsername_NotFound(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	user, err := repo.GetByUsername(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetByUsername failed: %v", err)
	}
	if user != nil {
		t.Error("expected nil for non-existent user")
	}
}

func TestUserRepository_UpdateLastLogin(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update last login
	err = repo.UpdateLastLogin(ctx, user.ID)
	if err != nil {
		t.Fatalf("UpdateLastLogin failed: %v", err)
	}

	// Verify by checking the raw value in the database
	// (since the date format from CURRENT_TIMESTAMP may differ from RFC3339)
	var lastLogin sql.NullString
	err = db.QueryRow("SELECT last_login FROM users WHERE id = ?", user.ID).Scan(&lastLogin)
	if err != nil {
		t.Fatalf("failed to query last_login: %v", err)
	}
	if !lastLogin.Valid {
		t.Error("expected last_login to be set")
	}
}

func TestUserRepository_UpdatePassword(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user with require_password_change = true
	user, err := repo.Create(ctx, "testuser", "test@example.com", "oldpassword", "user", true)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update password and clear the flag
	err = repo.UpdatePassword(ctx, user.ID, "newpassword", true)
	if err != nil {
		t.Fatalf("UpdatePassword failed: %v", err)
	}

	// Verify
	updated, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if updated.PasswordHash != "newpassword" {
		t.Errorf("expected new password hash, got %q", updated.PasswordHash)
	}
	if updated.RequirePasswordChange {
		t.Error("expected require_password_change to be false")
	}
}

func TestUserRepository_UpdatePasswordWithSessionInvalidation(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "oldpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Create a session
	err = repo.CreateSession(ctx, user.ID, "session-token-123", time.Now().Add(24*time.Hour), "127.0.0.1", "TestAgent")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Verify session exists
	session, err := repo.GetSession(ctx, "session-token-123")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to exist")
	}

	// Update password with session invalidation
	err = repo.UpdatePasswordWithSessionInvalidation(ctx, user.ID, "newpassword", true)
	if err != nil {
		t.Fatalf("UpdatePasswordWithSessionInvalidation failed: %v", err)
	}

	// Verify session is invalidated
	session, err = repo.GetSession(ctx, "session-token-123")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session != nil {
		t.Error("expected session to be invalidated")
	}

	// Verify password is updated
	updated, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if updated.PasswordHash != "newpassword" {
		t.Errorf("expected new password hash, got %q", updated.PasswordHash)
	}
}

func TestUserRepository_Update(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update user details
	err = repo.Update(ctx, user.ID, "updateduser", "updated@example.com", "admin")
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Verify
	updated, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if updated.Username != "updateduser" {
		t.Errorf("expected username 'updateduser', got %q", updated.Username)
	}
	if updated.Email != "updated@example.com" {
		t.Errorf("expected email 'updated@example.com', got %q", updated.Email)
	}
	if updated.Role != "admin" {
		t.Errorf("expected role 'admin', got %q", updated.Role)
	}
}

func TestUserRepository_Update_InvalidRole(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Try to update with invalid role
	err = repo.Update(ctx, user.ID, "testuser", "test@example.com", "superadmin")
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestUserRepository_SetActive(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Deactivate user
	err = repo.SetActive(ctx, user.ID, false)
	if err != nil {
		t.Fatalf("SetActive failed: %v", err)
	}

	// Verify
	updated, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if updated.IsActive {
		t.Error("expected user to be inactive")
	}

	// Reactivate
	err = repo.SetActive(ctx, user.ID, true)
	if err != nil {
		t.Fatalf("SetActive failed: %v", err)
	}

	// Verify
	updated, err = repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if !updated.IsActive {
		t.Error("expected user to be active")
	}
}

func TestUserRepository_GetAll(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create multiple users
	_, err := repo.Create(ctx, "user1", "user1@example.com", "hash1", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	_, err = repo.Create(ctx, "user2", "user2@example.com", "hash2", "admin", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get all with pagination
	users, total, err := repo.GetAll(ctx, 10, 0)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestUserRepository_GetAll_Pagination(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create multiple users
	for i := 0; i < 5; i++ {
		_, err := repo.Create(ctx, "user"+string(rune('a'+i)), "user"+string(rune('a'+i))+"@example.com", "hash", "user", false)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// Get first page
	users, total, err := repo.GetAll(ctx, 2, 0)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}

	// Get second page
	users, total, err = repo.GetAll(ctx, 2, 2)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}
}

func TestUserRepository_GetAll_InvalidPagination(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Negative limit should be clamped
	users, total, err := repo.GetAll(ctx, -5, 0)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}
}

// Session tests

func TestUserRepository_CreateSession(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Create a session
	expiresAt := time.Now().Add(24 * time.Hour)
	err = repo.CreateSession(ctx, user.ID, "session-token-abc", expiresAt, "192.168.1.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Verify session exists
	session, err := repo.GetSession(ctx, "session-token-abc")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session == nil {
		t.Fatal("expected session, got nil")
	}
	if session.UserID != user.ID {
		t.Errorf("expected user ID %d, got %d", user.ID, session.UserID)
	}
	if session.IPAddress != "192.168.1.1" {
		t.Errorf("expected IP '192.168.1.1', got %q", session.IPAddress)
	}
}

func TestUserRepository_GetSession_NotFound(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	session, err := repo.GetSession(ctx, "nonexistent-token")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session != nil {
		t.Error("expected nil for non-existent session")
	}
}

func TestUserRepository_GetSession_Expired(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Create an expired session
	expiresAt := time.Now().Add(-1 * time.Hour)
	err = repo.CreateSession(ctx, user.ID, "expired-token", expiresAt, "127.0.0.1", "Test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Should not return expired session
	session, err := repo.GetSession(ctx, "expired-token")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session != nil {
		t.Error("expected nil for expired session")
	}
}

func TestUserRepository_UpdateSessionActivity(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user and session
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err = repo.CreateSession(ctx, user.ID, "session-token", time.Now().Add(24*time.Hour), "127.0.0.1", "Test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Update activity
	err = repo.UpdateSessionActivity(ctx, "session-token")
	if err != nil {
		t.Fatalf("UpdateSessionActivity failed: %v", err)
	}
}

func TestUserRepository_DeleteSession(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user and session
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err = repo.CreateSession(ctx, user.ID, "session-token", time.Now().Add(24*time.Hour), "127.0.0.1", "Test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Delete session
	err = repo.DeleteSession(ctx, "session-token")
	if err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	// Verify session is gone
	session, err := repo.GetSession(ctx, "session-token")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session != nil {
		t.Error("expected session to be deleted")
	}
}

func TestUserRepository_DeleteSessionsByUserID(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user and multiple sessions
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	err = repo.CreateSession(ctx, user.ID, "session-1", time.Now().Add(24*time.Hour), "127.0.0.1", "Test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	err = repo.CreateSession(ctx, user.ID, "session-2", time.Now().Add(24*time.Hour), "127.0.0.2", "Test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Delete all sessions for user
	err = repo.DeleteSessionsByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteSessionsByUserID failed: %v", err)
	}

	// Verify all sessions are gone
	session1, _ := repo.GetSession(ctx, "session-1")
	session2, _ := repo.GetSession(ctx, "session-2")
	if session1 != nil || session2 != nil {
		t.Error("expected all sessions to be deleted")
	}
}

func TestUserRepository_CleanupExpiredSessions(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Create expired and valid sessions
	err = repo.CreateSession(ctx, user.ID, "expired-token", time.Now().Add(-1*time.Hour), "127.0.0.1", "Test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	err = repo.CreateSession(ctx, user.ID, "valid-token", time.Now().Add(24*time.Hour), "127.0.0.1", "Test")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Cleanup expired sessions
	err = repo.CleanupExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredSessions failed: %v", err)
	}

	// Verify only valid session remains
	validSession, _ := repo.GetSession(ctx, "valid-token")
	if validSession == nil {
		t.Error("expected valid session to remain")
	}
}

// User file operations tests

func TestUserRepository_GetFiles(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Insert test files directly (include uploader_ip to avoid NULL scan issues)
	expiresAt := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	_, err = db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, expires_at, user_id, uploader_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "code1", "file1.txt", "stored1.txt", 100, "text/plain", expiresAt, user.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to insert test file: %v", err)
	}

	// Get user files
	files, total, err := repo.GetFiles(ctx, user.ID, 10, 0)
	if err != nil {
		t.Fatalf("GetFiles failed: %v", err)
	}
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	if len(files) != 1 {
		t.Errorf("expected 1 file, got %d", len(files))
	}
	if files[0].OriginalFilename != "file1.txt" {
		t.Errorf("expected filename 'file1.txt', got %q", files[0].OriginalFilename)
	}
}

func TestUserRepository_DeleteFile(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Insert a test file (include uploader_ip to avoid NULL scan issues)
	expiresAt := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	result, err := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, expires_at, user_id, uploader_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "code1", "file1.txt", "stored1.txt", 100, "text/plain", expiresAt, user.ID, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to insert test file: %v", err)
	}
	fileID, _ := result.LastInsertId()

	// Delete the file
	deleted, err := repo.DeleteFile(ctx, fileID, user.ID)
	if err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}
	if deleted.OriginalFilename != "file1.txt" {
		t.Errorf("expected deleted filename 'file1.txt', got %q", deleted.OriginalFilename)
	}

	// Verify file is gone by checking count directly
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files WHERE user_id = ?", user.ID).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count files: %v", err)
	}
	if count != 0 {
		t.Error("expected file to be deleted")
	}
}

func TestUserRepository_DeleteFile_NotFound(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Try to delete non-existent file
	_, err = repo.DeleteFile(ctx, 99999, user.ID)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserRepository_DeleteFile_WrongUser(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create two users
	user1, _ := repo.Create(ctx, "user1", "user1@example.com", "hash", "user", false)
	user2, _ := repo.Create(ctx, "user2", "user2@example.com", "hash", "user", false)

	// Insert a file owned by user1 (include uploader_ip)
	expiresAt := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	result, _ := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, expires_at, user_id, uploader_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "code1", "file1.txt", "stored1.txt", 100, "text/plain", expiresAt, user1.ID, "127.0.0.1")
	fileID, _ := result.LastInsertId()

	// Try to delete with wrong user
	_, err := repo.DeleteFile(ctx, fileID, user2.ID)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound when deleting file owned by another user, got %v", err)
	}
}

func TestUserRepository_Delete(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, err := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Delete user
	err = repo.Delete(ctx, user.ID, "/tmp/uploads")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify user is gone
	deleted, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if deleted != nil {
		t.Error("expected user to be deleted")
	}
}

func TestUserRepository_Delete_NotFound(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	err := repo.Delete(ctx, 99999, "/tmp/uploads")
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserRepository_Delete_EmptyUploadDir(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, _ := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	// Try to delete with empty uploadDir
	err := repo.Delete(ctx, user.ID, "")
	if err == nil {
		t.Error("expected error for empty uploadDir")
	}
}

func TestUserRepository_UpdateFileName(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, _ := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	// Insert a test file (include uploader_ip)
	expiresAt := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	result, _ := db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, expires_at, user_id, uploader_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "code1", "oldname.txt", "stored1.txt", 100, "text/plain", expiresAt, user.ID, "127.0.0.1")
	fileID, _ := result.LastInsertId()

	// Update filename
	err := repo.UpdateFileName(ctx, fileID, user.ID, "newname.txt")
	if err != nil {
		t.Fatalf("UpdateFileName failed: %v", err)
	}

	// Verify by checking database directly
	var filename string
	err = db.QueryRow("SELECT original_filename FROM files WHERE id = ?", fileID).Scan(&filename)
	if err != nil {
		t.Fatalf("failed to query filename: %v", err)
	}
	if filename != "newname.txt" {
		t.Errorf("expected filename 'newname.txt', got %q", filename)
	}
}

func TestUserRepository_UpdateFileName_NotFound(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	user, _ := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	err := repo.UpdateFileName(ctx, 99999, user.ID, "newname.txt")
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserRepository_GetFileByClaimCode(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	// Create a user
	user, _ := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	// Insert a test file (include uploader_ip)
	expiresAt := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	_, _ = db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, expires_at, user_id, uploader_ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, "abc123", "file.txt", "stored.txt", 100, "text/plain", expiresAt, user.ID, "127.0.0.1")

	// Get file by claim code
	file, err := repo.GetFileByClaimCode(ctx, "abc123", user.ID)
	if err != nil {
		t.Fatalf("GetFileByClaimCode failed: %v", err)
	}
	if file == nil {
		t.Fatal("expected file, got nil")
	}
	if file.ClaimCode != "abc123" {
		t.Errorf("expected claim code 'abc123', got %q", file.ClaimCode)
	}
}

func TestUserRepository_GetFileByClaimCode_NotFound(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	repo := NewUserRepository(db)
	ctx := context.Background()

	user, _ := repo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	file, err := repo.GetFileByClaimCode(ctx, "nonexistent", user.ID)
	if err != nil {
		t.Fatalf("GetFileByClaimCode failed: %v", err)
	}
	if file != nil {
		t.Error("expected nil for non-existent file")
	}
}

// Ensure UserRepository implements the interface
func TestUserRepository_ImplementsInterface(t *testing.T) {
	db := setupUserTestDB(t)
	defer db.Close()

	var _ repository.UserRepository = NewUserRepository(db)
}
