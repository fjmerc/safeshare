package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// Helper to generate a valid token hash (64 hex chars = SHA-256)
func generateTokenHash(t *testing.T, token string) string {
	t.Helper()
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func TestAPITokenRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// First create a user
	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, err := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	repo := NewAPITokenRepository(db)

	tokenHash := generateTokenHash(t, "test-token-1")
	expiresAt := time.Now().Add(24 * time.Hour)

	token, err := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc1", "upload,download", "192.168.1.1", &expiresAt)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if token.ID == 0 {
		t.Error("expected ID to be set after creation")
	}
	if token.Name != "Test Token" {
		t.Errorf("Name mismatch: got %s", token.Name)
	}
	if token.TokenHash != tokenHash {
		t.Errorf("TokenHash mismatch")
	}
	if token.Scopes != "upload,download" {
		t.Errorf("Scopes mismatch: got %s", token.Scopes)
	}
	if !token.IsActive {
		t.Error("expected IsActive to be true")
	}
}

func TestAPITokenRepository_Create_Validation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	validHash := generateTokenHash(t, "test-token")

	tests := []struct {
		name        string
		userID      int64
		tokenName   string
		tokenHash   string
		tokenPrefix string
		scopes      string
		createdIP   string
		wantErr     bool
	}{
		{
			name:        "valid token",
			userID:      user.ID,
			tokenName:   "Valid Token",
			tokenHash:   validHash,
			tokenPrefix: "safeshare_abc",
			scopes:      "upload",
			createdIP:   "192.168.1.1",
			wantErr:     false,
		},
		{
			name:        "zero user_id",
			userID:      0,
			tokenName:   "Token",
			tokenHash:   validHash,
			tokenPrefix: "safeshare_abc",
			scopes:      "upload",
			createdIP:   "192.168.1.1",
			wantErr:     true,
		},
		{
			name:        "empty name",
			userID:      user.ID,
			tokenName:   "",
			tokenHash:   validHash,
			tokenPrefix: "safeshare_abc",
			scopes:      "upload",
			createdIP:   "192.168.1.1",
			wantErr:     true,
		},
		{
			name:        "invalid token hash length",
			userID:      user.ID,
			tokenName:   "Token",
			tokenHash:   "short",
			tokenPrefix: "safeshare_abc",
			scopes:      "upload",
			createdIP:   "192.168.1.1",
			wantErr:     true,
		},
		{
			name:        "empty token prefix",
			userID:      user.ID,
			tokenName:   "Token",
			tokenHash:   validHash,
			tokenPrefix: "",
			scopes:      "upload",
			createdIP:   "192.168.1.1",
			wantErr:     true,
		},
		{
			name:        "IP too long",
			userID:      user.ID,
			tokenName:   "Token",
			tokenHash:   validHash,
			tokenPrefix: "safeshare_abc",
			scopes:      "upload",
			createdIP:   "1234567890123456789012345678901234567890123456", // 46 chars > 45 max
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := repo.Create(ctx, tt.userID, tt.tokenName, tt.tokenHash, tt.tokenPrefix, tt.scopes, tt.createdIP, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAPITokenRepository_GetByHash(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	// Create token
	_, err := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get by hash
	token, err := repo.GetByHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetByHash failed: %v", err)
	}
	if token == nil {
		t.Fatal("expected token, got nil")
	}
	if token.TokenHash != tokenHash {
		t.Errorf("TokenHash mismatch")
	}
}

func TestAPITokenRepository_GetByHash_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	token, err := repo.GetByHash(ctx, generateTokenHash(t, "nonexistent"))
	if err != nil {
		t.Fatalf("GetByHash failed: %v", err)
	}
	if token != nil {
		t.Error("expected nil for nonexistent token")
	}
}

func TestAPITokenRepository_GetByHash_EmptyHash(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	token, err := repo.GetByHash(ctx, "")
	if err != nil {
		t.Fatalf("GetByHash failed: %v", err)
	}
	if token != nil {
		t.Error("expected nil for empty hash")
	}
}

func TestAPITokenRepository_GetByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	created, err := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get by ID
	token, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if token == nil {
		t.Fatal("expected token, got nil")
	}
	if token.ID != created.ID {
		t.Errorf("ID mismatch: got %d, want %d", token.ID, created.ID)
	}
}

func TestAPITokenRepository_GetByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	token, err := repo.GetByID(ctx, 99999)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if token != nil {
		t.Error("expected nil for nonexistent ID")
	}
}

func TestAPITokenRepository_UpdateLastUsed(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	created, err := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update last used
	err = repo.UpdateLastUsed(ctx, created.ID, "10.0.0.1")
	if err != nil {
		t.Fatalf("UpdateLastUsed failed: %v", err)
	}

	// Verify update
	token, _ := repo.GetByID(ctx, created.ID)
	if token.LastUsedAt == nil {
		t.Error("expected LastUsedAt to be set")
	}
	if token.LastUsedIP == nil || *token.LastUsedIP != "10.0.0.1" {
		t.Error("expected LastUsedIP to be 10.0.0.1")
	}
}

func TestAPITokenRepository_GetByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create multiple tokens
	for i := 0; i < 3; i++ {
		tokenHash := generateTokenHash(t, "test-token-"+string(rune('a'+i)))
		_, err := repo.Create(ctx, user.ID, "Token "+string(rune('A'+i)), tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
	}

	// Get by user ID
	tokens, err := repo.GetByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByUserID failed: %v", err)
	}

	if len(tokens) != 3 {
		t.Errorf("expected 3 tokens, got %d", len(tokens))
	}
}

func TestAPITokenRepository_CountByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Count before creating
	count, err := repo.CountByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountByUserID failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 tokens, got %d", count)
	}

	// Create tokens
	for i := 0; i < 2; i++ {
		tokenHash := generateTokenHash(t, "test-token-"+string(rune('a'+i)))
		_, _ = repo.Create(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	}

	// Count after creating
	count, err = repo.CountByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("CountByUserID failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 tokens, got %d", count)
	}
}

func TestAPITokenRepository_Revoke(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	created, err := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Revoke token
	err = repo.Revoke(ctx, created.ID, user.ID)
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Verify token is inactive (GetByHash should return nil for inactive)
	token, err := repo.GetByHash(ctx, tokenHash)
	if err != nil {
		t.Fatalf("GetByHash failed: %v", err)
	}
	if token != nil {
		t.Error("expected nil for revoked token")
	}

	// But GetByID should still find it (for admin)
	token, err = repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if token == nil {
		t.Fatal("expected to find revoked token by ID")
	}
	if token.IsActive {
		t.Error("expected IsActive to be false")
	}
}

func TestAPITokenRepository_Revoke_WrongUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user1, _ := userRepo.Create(ctx, "user1", "user1@example.com", "hashedpassword", "user", false)
	user2, _ := userRepo.Create(ctx, "user2", "user2@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	created, _ := repo.Create(ctx, user1.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Try to revoke with wrong user
	err := repo.Revoke(ctx, created.ID, user2.ID)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAPITokenRepository_RevokeAdmin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	created, _ := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Admin revoke (no user check)
	err := repo.RevokeAdmin(ctx, created.ID)
	if err != nil {
		t.Fatalf("RevokeAdmin failed: %v", err)
	}

	// Verify revoked
	token, _ := repo.GetByID(ctx, created.ID)
	if token.IsActive {
		t.Error("expected IsActive to be false")
	}
}

func TestAPITokenRepository_RevokeAdmin_NotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	err := repo.RevokeAdmin(ctx, 99999)
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAPITokenRepository_DeleteByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create tokens
	for i := 0; i < 3; i++ {
		tokenHash := generateTokenHash(t, "test-token-"+string(rune('a'+i)))
		_, _ = repo.Create(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	}

	// Delete all tokens for user
	err := repo.DeleteByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}

	// Verify deleted
	count, _ := repo.CountByUserID(ctx, user.ID)
	if count != 0 {
		t.Errorf("expected 0 tokens after delete, got %d", count)
	}
}

func TestAPITokenRepository_GetAllAdmin(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create tokens
	for i := 0; i < 5; i++ {
		tokenHash := generateTokenHash(t, "test-token-"+string(rune('a'+i)))
		_, _ = repo.Create(ctx, user.ID, "Token "+string(rune('A'+i)), tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	}

	// Get all with pagination
	tokens, total, err := repo.GetAllAdmin(ctx, 3, 0)
	if err != nil {
		t.Fatalf("GetAllAdmin failed: %v", err)
	}

	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(tokens) != 3 {
		t.Errorf("expected 3 tokens with limit, got %d", len(tokens))
	}

	// Verify username is populated
	if tokens[0].Username != "testuser" {
		t.Errorf("expected username 'testuser', got '%s'", tokens[0].Username)
	}
}

func TestAPITokenRepository_GetAllAdmin_Pagination(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create tokens
	for i := 0; i < 5; i++ {
		tokenHash := generateTokenHash(t, "test-token-"+string(rune('a'+i)))
		_, _ = repo.Create(ctx, user.ID, "Token "+string(rune('A'+i)), tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	}

	// Get second page
	tokens, _, err := repo.GetAllAdmin(ctx, 2, 2)
	if err != nil {
		t.Fatalf("GetAllAdmin failed: %v", err)
	}

	if len(tokens) != 2 {
		t.Errorf("expected 2 tokens on page 2, got %d", len(tokens))
	}
}

func TestAPITokenRepository_CleanupExpired(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create expired token
	expiredTime := time.Now().Add(-24 * time.Hour)
	tokenHash1 := generateTokenHash(t, "expired-token")
	_, _ = repo.Create(ctx, user.ID, "Expired Token", tokenHash1, "safeshare_abc", "upload", "192.168.1.1", &expiredTime)

	// Create valid token
	futureTime := time.Now().Add(24 * time.Hour)
	tokenHash2 := generateTokenHash(t, "valid-token")
	_, _ = repo.Create(ctx, user.ID, "Valid Token", tokenHash2, "safeshare_abc", "upload", "192.168.1.1", &futureTime)

	// Create never-expires token
	tokenHash3 := generateTokenHash(t, "never-expires")
	_, _ = repo.Create(ctx, user.ID, "Never Expires", tokenHash3, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Cleanup expired
	deleted, err := repo.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired failed: %v", err)
	}

	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	// Verify counts
	_, total, _ := repo.GetAllAdmin(ctx, 100, 0)
	if total != 2 {
		t.Errorf("expected 2 remaining tokens, got %d", total)
	}
}

func TestAPITokenRepository_Interface(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Verify APITokenRepository implements repository.APITokenRepository
	var _ repository.APITokenRepository = (*APITokenRepository)(nil)
}
