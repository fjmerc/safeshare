package database

import (
	"testing"
	"time"
)

// TestCreateAPIToken tests API token creation
func TestCreateAPIToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// First create a user to associate the token with
	user, err := CreateUser(db, "tokenuser", "tokenuser@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	token, err := CreateAPIToken(db, user.ID, "test-token", "hash123", "ss_", "files:read,files:write", "127.0.0.1", &expiresAt)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	if token.ID == 0 {
		t.Error("CreateAPIToken() did not set token ID")
	}

	if token.UserID != user.ID {
		t.Errorf("UserID = %d, want %d", token.UserID, user.ID)
	}

	if token.Name != "test-token" {
		t.Errorf("Name = %q, want %q", token.Name, "test-token")
	}

	if token.TokenHash != "hash123" {
		t.Errorf("TokenHash = %q, want %q", token.TokenHash, "hash123")
	}

	if token.TokenPrefix != "ss_" {
		t.Errorf("TokenPrefix = %q, want %q", token.TokenPrefix, "ss_")
	}

	if token.Scopes != "files:read,files:write" {
		t.Errorf("Scopes = %q, want %q", token.Scopes, "files:read,files:write")
	}

	if !token.IsActive {
		t.Error("IsActive should be true")
	}
}

// TestCreateAPIToken_NoExpiration tests creating token without expiration
func TestCreateAPIToken_NoExpiration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser2", "tokenuser2@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	token, err := CreateAPIToken(db, user.ID, "no-expire-token", "hash456", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	if token.ExpiresAt != nil {
		t.Error("ExpiresAt should be nil for non-expiring token")
	}
}

// TestGetAPITokenByHash tests retrieving token by hash
func TestGetAPITokenByHash(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser3", "tokenuser3@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	_, err = CreateAPIToken(db, user.ID, "find-token", "uniquehash", "ss_", "files:read", "127.0.0.1", &expiresAt)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	// Retrieve by hash
	token, err := GetAPITokenByHash(db, "uniquehash")
	if err != nil {
		t.Fatalf("GetAPITokenByHash() error: %v", err)
	}

	if token == nil {
		t.Fatal("GetAPITokenByHash() returned nil")
	}

	if token.Name != "find-token" {
		t.Errorf("Name = %q, want %q", token.Name, "find-token")
	}

	if token.TokenHash != "uniquehash" {
		t.Errorf("TokenHash = %q, want %q", token.TokenHash, "uniquehash")
	}
}

// TestGetAPITokenByHash_NotFound tests retrieving non-existent token
func TestGetAPITokenByHash_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	token, err := GetAPITokenByHash(db, "nonexistent")
	if err != nil {
		t.Fatalf("GetAPITokenByHash() error: %v", err)
	}

	if token != nil {
		t.Error("GetAPITokenByHash() should return nil for non-existent token")
	}
}

// TestUpdateAPITokenLastUsed tests updating token last used timestamp
func TestUpdateAPITokenLastUsed(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser4", "tokenuser4@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	created, err := CreateAPIToken(db, user.ID, "update-token", "updatehash", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	// Update last used
	err = UpdateAPITokenLastUsed(db, created.ID, "192.168.1.1")
	if err != nil {
		t.Fatalf("UpdateAPITokenLastUsed() error: %v", err)
	}

	// Retrieve and check
	token, err := GetAPITokenByHash(db, "updatehash")
	if err != nil {
		t.Fatalf("GetAPITokenByHash() error: %v", err)
	}

	if token.LastUsedAt == nil {
		t.Error("LastUsedAt should not be nil after update")
	}

	if token.LastUsedIP == nil || *token.LastUsedIP != "192.168.1.1" {
		t.Error("LastUsedIP should be '192.168.1.1'")
	}
}

// TestGetAPITokensByUserID tests retrieving tokens by user ID
func TestGetAPITokensByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser5", "tokenuser5@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create multiple tokens
	_, err = CreateAPIToken(db, user.ID, "token1", "hash1", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}
	_, err = CreateAPIToken(db, user.ID, "token2", "hash2", "ss_", "files:write", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	tokens, err := GetAPITokensByUserID(db, user.ID)
	if err != nil {
		t.Fatalf("GetAPITokensByUserID() error: %v", err)
	}

	if len(tokens) != 2 {
		t.Errorf("len(tokens) = %d, want 2", len(tokens))
	}
}

// TestRevokeAPIToken tests revoking a token
func TestRevokeAPIToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser6", "tokenuser6@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	created, err := CreateAPIToken(db, user.ID, "revoke-token", "revokehash", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	// Revoke the token
	err = RevokeAPIToken(db, created.ID, user.ID)
	if err != nil {
		t.Fatalf("RevokeAPIToken() error: %v", err)
	}

	// Try to retrieve - should return nil (inactive)
	token, err := GetAPITokenByHash(db, "revokehash")
	if err != nil {
		t.Fatalf("GetAPITokenByHash() error: %v", err)
	}

	if token != nil {
		t.Error("GetAPITokenByHash() should return nil for revoked token")
	}
}

// TestRevokeAPITokenAdmin tests admin revoking a token
func TestRevokeAPITokenAdmin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser7", "tokenuser7@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	created, err := CreateAPIToken(db, user.ID, "admin-revoke-token", "adminrevokehash", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	// Admin revoke
	err = RevokeAPITokenAdmin(db, created.ID)
	if err != nil {
		t.Fatalf("RevokeAPITokenAdmin() error: %v", err)
	}

	// Try to retrieve - should return nil (inactive)
	token, err := GetAPITokenByHash(db, "adminrevokehash")
	if err != nil {
		t.Fatalf("GetAPITokenByHash() error: %v", err)
	}

	if token != nil {
		t.Error("GetAPITokenByHash() should return nil for admin-revoked token")
	}
}

// TestDeleteAPITokenAdmin tests admin deleting a token
func TestDeleteAPITokenAdmin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser8", "tokenuser8@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	created, err := CreateAPIToken(db, user.ID, "delete-token", "deletehash", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	// Delete the token
	err = DeleteAPITokenAdmin(db, created.ID)
	if err != nil {
		t.Fatalf("DeleteAPITokenAdmin() error: %v", err)
	}

	// Verify it's gone - need to query directly since GetAPITokenByHash only returns active
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM api_tokens WHERE id = ?", created.ID).Scan(&count)
	if err != nil {
		t.Fatalf("query error: %v", err)
	}

	if count != 0 {
		t.Error("Token should be deleted")
	}
}

// TestDeleteAPITokensByUserID tests deleting all tokens for a user
func TestDeleteAPITokensByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser9", "tokenuser9@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create multiple tokens
	_, err = CreateAPIToken(db, user.ID, "token1", "userhash1", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}
	_, err = CreateAPIToken(db, user.ID, "token2", "userhash2", "ss_", "files:write", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	// Delete all tokens for user
	err = DeleteAPITokensByUserID(db, user.ID)
	if err != nil {
		t.Fatalf("DeleteAPITokensByUserID() error: %v", err)
	}

	// Verify all are gone
	tokens, err := GetAPITokensByUserID(db, user.ID)
	if err != nil {
		t.Fatalf("GetAPITokensByUserID() error: %v", err)
	}

	if len(tokens) != 0 {
		t.Errorf("len(tokens) = %d, want 0", len(tokens))
	}
}

// TestCountAPITokensByUserID tests counting tokens for a user
func TestCountAPITokensByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser10", "tokenuser10@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create tokens
	_, err = CreateAPIToken(db, user.ID, "token1", "counthash1", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}
	_, err = CreateAPIToken(db, user.ID, "token2", "counthash2", "ss_", "files:write", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	count, err := CountAPITokensByUserID(db, user.ID)
	if err != nil {
		t.Fatalf("CountAPITokensByUserID() error: %v", err)
	}

	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

// TestGetAPITokenByID tests retrieving token by ID
func TestGetAPITokenByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser11", "tokenuser11@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	created, err := CreateAPIToken(db, user.ID, "id-token", "idhash", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	token, err := GetAPITokenByID(db, created.ID)
	if err != nil {
		t.Fatalf("GetAPITokenByID() error: %v", err)
	}

	if token == nil {
		t.Fatal("GetAPITokenByID() returned nil")
	}

	if token.Name != "id-token" {
		t.Errorf("Name = %q, want %q", token.Name, "id-token")
	}
}

// TestGetAPITokenByID_NotFound tests retrieving non-existent token by ID
func TestGetAPITokenByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	token, err := GetAPITokenByID(db, 99999)
	if err != nil {
		t.Fatalf("GetAPITokenByID() error: %v", err)
	}

	if token != nil {
		t.Error("GetAPITokenByID() should return nil for non-existent token")
	}
}

// TestGetAllAPITokensAdmin tests admin retrieval of all tokens
func TestGetAllAPITokensAdmin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user1, err := CreateUser(db, "tokenadmin1", "tokenadmin1@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}
	user2, err := CreateUser(db, "tokenadmin2", "tokenadmin2@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create tokens for different users
	_, err = CreateAPIToken(db, user1.ID, "user1-token", "adminhash1", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}
	_, err = CreateAPIToken(db, user2.ID, "user2-token", "adminhash2", "ss_", "files:read", "127.0.0.1", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	tokens, total, err := GetAllAPITokensAdmin(db, 10, 0)
	if err != nil {
		t.Fatalf("GetAllAPITokensAdmin() error: %v", err)
	}

	if len(tokens) < 2 {
		t.Errorf("len(tokens) = %d, want >= 2", len(tokens))
	}

	if total < 2 {
		t.Errorf("total = %d, want >= 2", total)
	}
}

// TestCleanupExpiredAPITokens tests cleaning up expired tokens
func TestCleanupExpiredAPITokens(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	user, err := CreateUser(db, "tokenuser12", "tokenuser12@example.com", "hashed_password", "user", false)
	if err != nil {
		t.Fatalf("CreateUser() error: %v", err)
	}

	// Create an expired token
	expiredTime := time.Now().Add(-24 * time.Hour)
	_, err = CreateAPIToken(db, user.ID, "expired-token", "expiredhash", "ss_", "files:read", "127.0.0.1", &expiredTime)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	// Create a valid token
	validTime := time.Now().Add(24 * time.Hour)
	_, err = CreateAPIToken(db, user.ID, "valid-token", "validhash", "ss_", "files:read", "127.0.0.1", &validTime)
	if err != nil {
		t.Fatalf("CreateAPIToken() error: %v", err)
	}

	// Cleanup expired tokens
	deleted, err := CleanupExpiredAPITokens(db)
	if err != nil {
		t.Fatalf("CleanupExpiredAPITokens() error: %v", err)
	}

	if deleted < 1 {
		t.Errorf("deleted = %d, want >= 1", deleted)
	}

	// Verify valid token still exists
	tokens, err := GetAPITokensByUserID(db, user.ID)
	if err != nil {
		t.Fatalf("GetAPITokensByUserID() error: %v", err)
	}

	// Should have at least the valid token
	foundValid := false
	for _, token := range tokens {
		if token.Name == "valid-token" {
			foundValid = true
			break
		}
	}

	if !foundValid {
		t.Error("Valid token should not be deleted")
	}
}
