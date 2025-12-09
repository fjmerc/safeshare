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

func TestAPITokenRepository_GetUsageStats(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	// Create a token
	token, err := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Get stats for token with no usage
	stats, err := repo.GetUsageStats(ctx, token.ID)
	if err != nil {
		t.Fatalf("GetUsageStats failed: %v", err)
	}

	if stats.TotalRequests != 0 {
		t.Errorf("expected TotalRequests 0, got %d", stats.TotalRequests)
	}
	if stats.Last24hRequests != 0 {
		t.Errorf("expected Last24hRequests 0, got %d", stats.Last24hRequests)
	}
	if stats.UniqueIPs != 0 {
		t.Errorf("expected UniqueIPs 0, got %d", stats.UniqueIPs)
	}
	if len(stats.TopEndpoints) != 0 {
		t.Errorf("expected 0 TopEndpoints, got %d", len(stats.TopEndpoints))
	}
}

func TestAPITokenRepository_GetUsageStats_WithUsage(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	// Create a token
	token, err := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Log usage from different IPs and endpoints
	// Endpoint 1: 5 requests from 2 IPs
	for i := 0; i < 3; i++ {
		_ = repo.LogUsage(ctx, token.ID, "/api/upload", "192.168.1.100", "Test-Agent", 200)
	}
	for i := 0; i < 2; i++ {
		_ = repo.LogUsage(ctx, token.ID, "/api/upload", "192.168.1.101", "Test-Agent", 200)
	}

	// Endpoint 2: 3 requests from 1 IP
	for i := 0; i < 3; i++ {
		_ = repo.LogUsage(ctx, token.ID, "/api/download", "192.168.1.100", "Test-Agent", 200)
	}

	// Endpoint 3: 2 requests
	for i := 0; i < 2; i++ {
		_ = repo.LogUsage(ctx, token.ID, "/api/files", "192.168.1.102", "Test-Agent", 200)
	}

	// Get stats
	stats, err := repo.GetUsageStats(ctx, token.ID)
	if err != nil {
		t.Fatalf("GetUsageStats failed: %v", err)
	}

	// Total: 5 + 3 + 2 = 10 requests
	if stats.TotalRequests != 10 {
		t.Errorf("expected TotalRequests 10, got %d", stats.TotalRequests)
	}

	// All should be within last 24h
	if stats.Last24hRequests != 10 {
		t.Errorf("expected Last24hRequests 10, got %d", stats.Last24hRequests)
	}

	// Unique IPs: 192.168.1.100, 192.168.1.101, 192.168.1.102 = 3
	if stats.UniqueIPs != 3 {
		t.Errorf("expected UniqueIPs 3, got %d", stats.UniqueIPs)
	}

	// Top endpoints should be sorted by count
	if len(stats.TopEndpoints) < 3 {
		t.Fatalf("expected at least 3 TopEndpoints, got %d", len(stats.TopEndpoints))
	}

	// First should be /api/upload with 5 requests
	if stats.TopEndpoints[0].Endpoint != "/api/upload" {
		t.Errorf("expected first endpoint to be /api/upload, got %s", stats.TopEndpoints[0].Endpoint)
	}
	if stats.TopEndpoints[0].Count != 5 {
		t.Errorf("expected /api/upload count 5, got %d", stats.TopEndpoints[0].Count)
	}

	// Second should be /api/download with 3 requests
	if stats.TopEndpoints[1].Endpoint != "/api/download" {
		t.Errorf("expected second endpoint to be /api/download, got %s", stats.TopEndpoints[1].Endpoint)
	}
	if stats.TopEndpoints[1].Count != 3 {
		t.Errorf("expected /api/download count 3, got %d", stats.TopEndpoints[1].Count)
	}
}

func TestAPITokenRepository_GetUsageStats_InvalidTokenID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	// Test with zero token ID
	_, err := repo.GetUsageStats(ctx, 0)
	if err == nil {
		t.Error("expected error for zero token ID")
	}

	// Test with negative token ID
	_, err = repo.GetUsageStats(ctx, -1)
	if err == nil {
		t.Error("expected error for negative token ID")
	}
}

func TestAPITokenRepository_GetUsageStats_NonExistentToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	// Get stats for non-existent token (should return empty stats, not error)
	stats, err := repo.GetUsageStats(ctx, 99999)
	if err != nil {
		t.Fatalf("GetUsageStats failed: %v", err)
	}

	if stats.TotalRequests != 0 {
		t.Errorf("expected TotalRequests 0 for non-existent token, got %d", stats.TotalRequests)
	}
}

func TestAPITokenRepository_GetUsageStats_TopEndpointsLimit(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")

	// Create a token
	token, err := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Log usage to 10 different endpoints
	for i := 0; i < 10; i++ {
		endpoint := "/api/endpoint" + string(rune('A'+i))
		for j := 0; j <= i; j++ { // Each endpoint gets (i+1) requests
			_ = repo.LogUsage(ctx, token.ID, endpoint, "192.168.1.100", "Test-Agent", 200)
		}
	}

	// Get stats
	stats, err := repo.GetUsageStats(ctx, token.ID)
	if err != nil {
		t.Fatalf("GetUsageStats failed: %v", err)
	}

	// Should only return top 5 endpoints
	if len(stats.TopEndpoints) != 5 {
		t.Errorf("expected exactly 5 TopEndpoints, got %d", len(stats.TopEndpoints))
	}

	// First endpoint should have the most requests (10)
	if stats.TopEndpoints[0].Count != 10 {
		t.Errorf("expected first endpoint to have 10 requests, got %d", stats.TopEndpoints[0].Count)
	}
}

func TestAPITokenRepository_GetUsageStatsBatch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create multiple tokens
	var tokenIDs []int64
	for i := 0; i < 3; i++ {
		tokenHash := generateTokenHash(t, "test-token-"+string(rune('a'+i)))
		token, err := repo.Create(ctx, user.ID, "Token "+string(rune('A'+i)), tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		tokenIDs = append(tokenIDs, token.ID)

		// Add usage for each token (different amounts)
		for j := 0; j <= i; j++ {
			_ = repo.LogUsage(ctx, token.ID, "/api/test", "192.168.1.100", "Test-Agent", 200)
		}
	}

	// Get batch stats
	statsMap, err := repo.GetUsageStatsBatch(ctx, tokenIDs)
	if err != nil {
		t.Fatalf("GetUsageStatsBatch failed: %v", err)
	}

	// Verify all tokens have stats
	if len(statsMap) != 3 {
		t.Errorf("expected 3 stats entries, got %d", len(statsMap))
	}

	// Verify counts are correct
	for i, tokenID := range tokenIDs {
		stats, ok := statsMap[tokenID]
		if !ok {
			t.Errorf("missing stats for token %d", tokenID)
			continue
		}
		expectedCount := int64(i + 1) // Token 0 has 1 req, token 1 has 2 reqs, token 2 has 3 reqs
		if stats.TotalRequests != expectedCount {
			t.Errorf("token %d: expected TotalRequests %d, got %d", tokenID, expectedCount, stats.TotalRequests)
		}
	}
}

func TestAPITokenRepository_GetUsageStatsBatch_EmptyList(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	// Get batch stats with empty list
	statsMap, err := repo.GetUsageStatsBatch(ctx, []int64{})
	if err != nil {
		t.Fatalf("GetUsageStatsBatch failed: %v", err)
	}

	if len(statsMap) != 0 {
		t.Errorf("expected empty map, got %d entries", len(statsMap))
	}
}

func TestAPITokenRepository_GetUsageStatsBatch_NoUsage(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create tokens without any usage
	var tokenIDs []int64
	for i := 0; i < 2; i++ {
		tokenHash := generateTokenHash(t, "test-token-"+string(rune('a'+i)))
		token, _ := repo.Create(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
		tokenIDs = append(tokenIDs, token.ID)
	}

	// Get batch stats
	statsMap, err := repo.GetUsageStatsBatch(ctx, tokenIDs)
	if err != nil {
		t.Fatalf("GetUsageStatsBatch failed: %v", err)
	}

	// Verify all tokens have empty stats
	for _, tokenID := range tokenIDs {
		stats, ok := statsMap[tokenID]
		if !ok {
			t.Errorf("missing stats entry for token %d", tokenID)
			continue
		}
		if stats.TotalRequests != 0 {
			t.Errorf("expected TotalRequests 0, got %d", stats.TotalRequests)
		}
		if len(stats.TopEndpoints) != 0 {
			t.Errorf("expected 0 TopEndpoints, got %d", len(stats.TopEndpoints))
		}
	}
}

// ============================================================================
// Token Rotation Tests (Task 3.3.1)
// ============================================================================

func TestAPITokenRepository_Rotate(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create a token with specific scopes and expiration
	originalHash := generateTokenHash(t, "original-token")
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	token, err := repo.Create(ctx, user.ID, "Test Token", originalHash, "safeshare_old1", "upload,download", "192.168.1.1", &expiresAt)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update last used to verify it gets cleared
	_ = repo.UpdateLastUsed(ctx, token.ID, "192.168.1.100")

	// Rotate the token
	newHash := generateTokenHash(t, "new-token")
	newPrefix := "safeshare_new1"
	rotatedToken, err := repo.Rotate(ctx, token.ID, user.ID, newHash, newPrefix)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// Verify metadata is preserved
	if rotatedToken.ID != token.ID {
		t.Errorf("ID should be preserved: got %d, want %d", rotatedToken.ID, token.ID)
	}
	if rotatedToken.Name != "Test Token" {
		t.Errorf("Name should be preserved: got %s", rotatedToken.Name)
	}
	if rotatedToken.Scopes != "upload,download" {
		t.Errorf("Scopes should be preserved: got %s", rotatedToken.Scopes)
	}
	if rotatedToken.ExpiresAt == nil {
		t.Error("ExpiresAt should be preserved")
	}

	// Verify credentials are updated
	if rotatedToken.TokenHash != newHash {
		t.Error("TokenHash should be updated")
	}
	if rotatedToken.TokenPrefix != newPrefix {
		t.Errorf("TokenPrefix should be updated: got %s, want %s", rotatedToken.TokenPrefix, newPrefix)
	}

	// Verify last_used is cleared
	if rotatedToken.LastUsedAt != nil {
		t.Error("LastUsedAt should be cleared after rotation")
	}
	if rotatedToken.LastUsedIP != nil {
		t.Error("LastUsedIP should be cleared after rotation")
	}

	// Verify old token no longer works
	oldTokenLookup, _ := repo.GetByHash(ctx, originalHash)
	if oldTokenLookup != nil {
		t.Error("Old token hash should not be found")
	}

	// Verify new token works
	newTokenLookup, err := repo.GetByHash(ctx, newHash)
	if err != nil {
		t.Fatalf("GetByHash failed: %v", err)
	}
	if newTokenLookup == nil {
		t.Error("New token hash should be found")
	}
}

func TestAPITokenRepository_Rotate_WrongUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user1, _ := userRepo.Create(ctx, "user1", "user1@example.com", "hashedpassword", "user", false)
	user2, _ := userRepo.Create(ctx, "user2", "user2@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")
	token, _ := repo.Create(ctx, user1.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Try to rotate with wrong user
	newHash := generateTokenHash(t, "new-token")
	_, err := repo.Rotate(ctx, token.ID, user2.ID, newHash, "safeshare_new")
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAPITokenRepository_Rotate_InactiveToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")
	token, _ := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Revoke the token first
	_ = repo.Revoke(ctx, token.ID, user.ID)

	// Try to rotate revoked token
	newHash := generateTokenHash(t, "new-token")
	_, err := repo.Rotate(ctx, token.ID, user.ID, newHash, "safeshare_new")
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAPITokenRepository_Rotate_NonExistent(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	newHash := generateTokenHash(t, "new-token")
	_, err := repo.Rotate(ctx, 99999, 1, newHash, "safeshare_new")
	if err != repository.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAPITokenRepository_Rotate_InvalidInputs(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()
	validHash := generateTokenHash(t, "valid-token")

	tests := []struct {
		name      string
		tokenID   int64
		userID    int64
		newHash   string
		newPrefix string
	}{
		{"zero token_id", 0, 1, validHash, "safeshare_new"},
		{"negative token_id", -1, 1, validHash, "safeshare_new"},
		{"zero user_id", 1, 0, validHash, "safeshare_new"},
		{"negative user_id", 1, -1, validHash, "safeshare_new"},
		{"empty hash", 1, 1, "", "safeshare_new"},
		{"short hash", 1, 1, "tooshort", "safeshare_new"},
		{"empty prefix", 1, 1, validHash, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := repo.Rotate(ctx, tt.tokenID, tt.userID, tt.newHash, tt.newPrefix)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

// ============================================================================
// CreateWithLimit Tests (Task 3.3.4)
// ============================================================================

func TestAPITokenRepository_CreateWithLimit(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create first token with limit of 3
	tokenHash := generateTokenHash(t, "token-1")
	token, err := repo.CreateWithLimit(ctx, user.ID, "Token 1", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil, 3)
	if err != nil {
		t.Fatalf("CreateWithLimit failed: %v", err)
	}

	if token.ID == 0 {
		t.Error("expected ID to be set")
	}
	if token.Name != "Token 1" {
		t.Errorf("Name mismatch: got %s", token.Name)
	}
	if !token.IsActive {
		t.Error("expected IsActive to be true")
	}
}

func TestAPITokenRepository_CreateWithLimit_AtLimit(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create 2 tokens with limit of 2
	for i := 0; i < 2; i++ {
		tokenHash := generateTokenHash(t, "token-"+string(rune('a'+i)))
		_, err := repo.CreateWithLimit(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil, 2)
		if err != nil {
			t.Fatalf("CreateWithLimit failed for token %d: %v", i+1, err)
		}
	}

	// Try to create a third token - should fail
	tokenHash := generateTokenHash(t, "token-c")
	_, err := repo.CreateWithLimit(ctx, user.ID, "Token 3", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil, 2)
	if err != repository.ErrTooManyTokens {
		t.Errorf("expected ErrTooManyTokens, got %v", err)
	}
}

func TestAPITokenRepository_CreateWithLimit_InvalidMaxTokens(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "token")

	// Zero maxTokens should error
	_, err := repo.CreateWithLimit(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil, 0)
	if err == nil {
		t.Error("expected error for zero maxTokens")
	}

	// Negative maxTokens should error
	_, err = repo.CreateWithLimit(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil, -1)
	if err == nil {
		t.Error("expected error for negative maxTokens")
	}
}

func TestAPITokenRepository_CreateWithLimit_RevokedTokensDontCount(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create 2 tokens with limit of 2
	for i := 0; i < 2; i++ {
		tokenHash := generateTokenHash(t, "token-"+string(rune('a'+i)))
		_, _ = repo.CreateWithLimit(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil, 2)
	}

	// Revoke one token
	tokens, _ := repo.GetByUserID(ctx, user.ID)
	if len(tokens) > 0 {
		_ = repo.Revoke(ctx, tokens[0].ID, user.ID)
	}

	// Now should be able to create another token (revoked don't count)
	tokenHash := generateTokenHash(t, "token-c")
	_, err := repo.CreateWithLimit(ctx, user.ID, "Token 3", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil, 2)
	if err != nil {
		t.Errorf("CreateWithLimit should succeed after revoking: %v", err)
	}
}

// ============================================================================
// Audit Logging Tests (Task 3.3.2)
// ============================================================================

func TestAPITokenRepository_LogUsage(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")
	token, _ := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Log usage
	err := repo.LogUsage(ctx, token.ID, "/api/upload", "192.168.1.100", "curl/7.68.0", 200)
	if err != nil {
		t.Fatalf("LogUsage failed: %v", err)
	}

	// Verify log was created
	logs, total, err := repo.GetUsageLogs(ctx, token.ID, repository.UsageFilter{Limit: 10})
	if err != nil {
		t.Fatalf("GetUsageLogs failed: %v", err)
	}

	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(logs))
	}
	if logs[0].Endpoint != "/api/upload" {
		t.Errorf("Endpoint mismatch: got %s", logs[0].Endpoint)
	}
	if logs[0].IPAddress != "192.168.1.100" {
		t.Errorf("IPAddress mismatch: got %s", logs[0].IPAddress)
	}
	if logs[0].ResponseStatus != 200 {
		t.Errorf("ResponseStatus mismatch: got %d", logs[0].ResponseStatus)
	}
}

func TestAPITokenRepository_LogUsage_Validation(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	tests := []struct {
		name     string
		tokenID  int64
		endpoint string
		ip       string
		agent    string
		status   int
		wantErr  bool
	}{
		{"zero token_id", 0, "/api/test", "192.168.1.1", "agent", 200, true},
		{"negative token_id", -1, "/api/test", "192.168.1.1", "agent", 200, true},
		{"empty endpoint", 1, "", "192.168.1.1", "agent", 200, true},
		{"invalid status too low", 1, "/api/test", "192.168.1.1", "agent", 99, true},
		{"invalid status too high", 1, "/api/test", "192.168.1.1", "agent", 600, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.LogUsage(ctx, tt.tokenID, tt.endpoint, tt.ip, tt.agent, tt.status)
			if (err != nil) != tt.wantErr {
				t.Errorf("LogUsage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAPITokenRepository_GetUsageLogs_DateFilter(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")
	token, _ := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Log multiple usage entries
	for i := 0; i < 5; i++ {
		_ = repo.LogUsage(ctx, token.ID, "/api/endpoint"+string(rune('A'+i)), "192.168.1.100", "agent", 200)
	}

	// Get all logs
	logs, total, err := repo.GetUsageLogs(ctx, token.ID, repository.UsageFilter{Limit: 100})
	if err != nil {
		t.Fatalf("GetUsageLogs failed: %v", err)
	}

	if total != 5 {
		t.Errorf("expected total 5, got %d", total)
	}
	if len(logs) != 5 {
		t.Errorf("expected 5 logs, got %d", len(logs))
	}

	// Test pagination
	logs, _, err = repo.GetUsageLogs(ctx, token.ID, repository.UsageFilter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("GetUsageLogs failed: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 logs with limit, got %d", len(logs))
	}

	logs, _, err = repo.GetUsageLogs(ctx, token.ID, repository.UsageFilter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("GetUsageLogs failed: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("expected 2 logs with offset, got %d", len(logs))
	}
}

func TestAPITokenRepository_GetUsageLogs_InvalidTokenID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	_, _, err := repo.GetUsageLogs(ctx, 0, repository.UsageFilter{})
	if err == nil {
		t.Error("expected error for zero token_id")
	}

	_, _, err = repo.GetUsageLogs(ctx, -1, repository.UsageFilter{})
	if err == nil {
		t.Error("expected error for negative token_id")
	}
}

func TestAPITokenRepository_CleanupOldUsageLogs(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)
	tokenHash := generateTokenHash(t, "test-token")
	token, _ := repo.Create(ctx, user.ID, "Test Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Log some usage
	for i := 0; i < 3; i++ {
		_ = repo.LogUsage(ctx, token.ID, "/api/test", "192.168.1.100", "agent", 200)
	}

	// Cleanup with future date (should delete all)
	deleted, err := repo.CleanupOldUsageLogs(ctx, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CleanupOldUsageLogs failed: %v", err)
	}

	if deleted != 3 {
		t.Errorf("expected 3 deleted, got %d", deleted)
	}

	// Verify logs are deleted
	_, total, _ := repo.GetUsageLogs(ctx, token.ID, repository.UsageFilter{})
	if total != 0 {
		t.Errorf("expected 0 logs after cleanup, got %d", total)
	}
}

// ============================================================================
// Bulk Operations Tests (Task 3.3.5)
// ============================================================================

func TestAPITokenRepository_RevokeMultiple(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create multiple tokens
	var tokenIDs []int64
	for i := 0; i < 5; i++ {
		tokenHash := generateTokenHash(t, "token-"+string(rune('a'+i)))
		token, _ := repo.Create(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
		tokenIDs = append(tokenIDs, token.ID)
	}

	// Revoke some tokens
	revoked, err := repo.RevokeMultiple(ctx, tokenIDs[:3])
	if err != nil {
		t.Fatalf("RevokeMultiple failed: %v", err)
	}

	if revoked != 3 {
		t.Errorf("expected 3 revoked, got %d", revoked)
	}

	// Verify count of active tokens
	count, _ := repo.CountByUserID(ctx, user.ID)
	if count != 2 {
		t.Errorf("expected 2 active tokens remaining, got %d", count)
	}
}

func TestAPITokenRepository_RevokeMultiple_Empty(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	revoked, err := repo.RevokeMultiple(ctx, []int64{})
	if err != nil {
		t.Fatalf("RevokeMultiple failed: %v", err)
	}

	if revoked != 0 {
		t.Errorf("expected 0 revoked for empty list, got %d", revoked)
	}
}

func TestAPITokenRepository_RevokeMultiple_SomeNotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create one token
	tokenHash := generateTokenHash(t, "token")
	token, _ := repo.Create(ctx, user.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)

	// Revoke with mix of real and non-existent IDs
	revoked, err := repo.RevokeMultiple(ctx, []int64{token.ID, 99999, 99998})
	if err != nil {
		t.Fatalf("RevokeMultiple failed: %v", err)
	}

	// Should only revoke the one real token
	if revoked != 1 {
		t.Errorf("expected 1 revoked, got %d", revoked)
	}
}

func TestAPITokenRepository_RevokeMultiple_InvalidTokenID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	_, err := repo.RevokeMultiple(ctx, []int64{1, 0, 3})
	if err == nil {
		t.Error("expected error for zero token_id in list")
	}

	_, err = repo.RevokeMultiple(ctx, []int64{1, -1, 3})
	if err == nil {
		t.Error("expected error for negative token_id in list")
	}
}

func TestAPITokenRepository_RevokeAllByUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user1, _ := userRepo.Create(ctx, "user1", "user1@example.com", "hashedpassword", "user", false)
	user2, _ := userRepo.Create(ctx, "user2", "user2@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Create tokens for both users
	for i := 0; i < 3; i++ {
		tokenHash := generateTokenHash(t, "user1-token-"+string(rune('a'+i)))
		_, _ = repo.Create(ctx, user1.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	}
	for i := 0; i < 2; i++ {
		tokenHash := generateTokenHash(t, "user2-token-"+string(rune('a'+i)))
		_, _ = repo.Create(ctx, user2.ID, "Token", tokenHash, "safeshare_abc", "upload", "192.168.1.1", nil)
	}

	// Revoke all tokens for user1
	revoked, err := repo.RevokeAllByUserID(ctx, user1.ID)
	if err != nil {
		t.Fatalf("RevokeAllByUserID failed: %v", err)
	}

	if revoked != 3 {
		t.Errorf("expected 3 revoked, got %d", revoked)
	}

	// Verify user1 has no active tokens
	count1, _ := repo.CountByUserID(ctx, user1.ID)
	if count1 != 0 {
		t.Errorf("expected 0 active tokens for user1, got %d", count1)
	}

	// Verify user2 still has tokens
	count2, _ := repo.CountByUserID(ctx, user2.ID)
	if count2 != 2 {
		t.Errorf("expected 2 active tokens for user2, got %d", count2)
	}
}

func TestAPITokenRepository_RevokeAllByUserID_NoTokens(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := NewUserRepository(db)
	ctx := context.Background()
	user, _ := userRepo.Create(ctx, "testuser", "test@example.com", "hashedpassword", "user", false)

	repo := NewAPITokenRepository(db)

	// Revoke for user with no tokens
	revoked, err := repo.RevokeAllByUserID(ctx, user.ID)
	if err != nil {
		t.Fatalf("RevokeAllByUserID failed: %v", err)
	}

	if revoked != 0 {
		t.Errorf("expected 0 revoked, got %d", revoked)
	}
}

func TestAPITokenRepository_RevokeAllByUserID_InvalidUserID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repo := NewAPITokenRepository(db)
	ctx := context.Background()

	_, err := repo.RevokeAllByUserID(ctx, 0)
	if err == nil {
		t.Error("expected error for zero user_id")
	}

	_, err = repo.RevokeAllByUserID(ctx, -1)
	if err == nil {
		t.Error("expected error for negative user_id")
	}
}
