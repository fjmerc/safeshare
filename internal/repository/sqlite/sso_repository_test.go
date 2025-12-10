package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/fjmerc/safeshare/internal/repository"
)

// setupSSOTestDB creates a test database with required SSO schema
func setupSSOTestDB(t *testing.T) *sql.DB {
	t.Helper()

	// Use a shared in-memory database
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&_txlock=immediate&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Create users table (required for foreign key)
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

	// Create sso_providers table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sso_providers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			slug TEXT NOT NULL UNIQUE,
			type TEXT NOT NULL DEFAULT 'oidc',
			enabled INTEGER NOT NULL DEFAULT 0,
			client_id TEXT,
			client_secret TEXT,
			issuer_url TEXT,
			authorization_url TEXT,
			token_url TEXT,
			userinfo_url TEXT,
			jwks_url TEXT,
			scopes TEXT DEFAULT 'openid profile email',
			redirect_url TEXT,
			auto_provision INTEGER NOT NULL DEFAULT 0,
			default_role TEXT DEFAULT 'user',
			domain_allowlist TEXT,
			icon_url TEXT,
			button_color TEXT,
			button_text_color TEXT,
			display_order INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("failed to create sso_providers table: %v", err)
	}

	// Create user_sso_links table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS user_sso_links (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			provider_id INTEGER NOT NULL,
			external_id TEXT NOT NULL,
			external_email TEXT,
			external_name TEXT,
			access_token TEXT,
			refresh_token TEXT,
			token_expires_at DATETIME,
			last_login_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE,
			UNIQUE (provider_id, external_id)
		)
	`)
	if err != nil {
		t.Fatalf("failed to create user_sso_links table: %v", err)
	}

	// Create sso_states table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sso_states (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			state TEXT NOT NULL UNIQUE,
			nonce TEXT NOT NULL,
			provider_id INTEGER NOT NULL,
			return_url TEXT,
			user_id INTEGER,
			created_ip TEXT,
			expires_at DATETIME NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
		)
	`)
	if err != nil {
		t.Fatalf("failed to create sso_states table: %v", err)
	}

	// Create test user
	_, err = db.Exec(`INSERT INTO users (username, email, password_hash, role) VALUES ('testuser', 'test@example.com', 'hash', 'user')`)
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	return db
}

// createTestProvider is a helper to create a valid provider input
func createTestProvider(name, slug string) *repository.CreateSSOProviderInput {
	return &repository.CreateSSOProviderInput{
		Name:        name,
		Slug:        slug,
		Type:        repository.SSOProviderTypeOIDC,
		Enabled:     true,
		ClientID:    "test-client-id",
		IssuerURL:   "https://example.com",
		Scopes:      "openid profile email",
		DefaultRole: "user",
	}
}

// ===========================================================================
// SSO Provider Operation Tests
// ===========================================================================

func TestSSORepository_CreateProvider_Valid(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	input := createTestProvider("Google", "google")
	input.ButtonColor = "#4285f4"
	input.ButtonTextColor = "#ffffff"
	input.IconURL = "https://example.com/icon.png"

	provider, err := repo.CreateProvider(ctx, input)
	if err != nil {
		t.Fatalf("CreateProvider failed: %v", err)
	}
	if provider.ID == 0 {
		t.Error("expected provider ID to be set")
	}
	if provider.Name != "Google" {
		t.Errorf("expected name 'Google', got %q", provider.Name)
	}
	if provider.Slug != "google" {
		t.Errorf("expected slug 'google', got %q", provider.Slug)
	}
	if !provider.Enabled {
		t.Error("expected provider to be enabled")
	}
	if provider.ButtonColor != "#4285f4" {
		t.Errorf("expected button color '#4285f4', got %q", provider.ButtonColor)
	}
}

func TestSSORepository_CreateProvider_NilInput(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.CreateProvider(ctx, nil)
	if err == nil {
		t.Error("expected error for nil input")
	}
}

func TestSSORepository_CreateProvider_DuplicateSlug(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Create first provider
	_, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create first provider: %v", err)
	}

	// Try to create with same slug
	_, err = repo.CreateProvider(ctx, createTestProvider("Google Auth", "google"))
	if err != repository.ErrSSOProviderSlugExists {
		t.Errorf("expected ErrSSOProviderSlugExists, got %v", err)
	}
}

func TestSSORepository_CreateProvider_InvalidSlugFormat(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	tests := []struct {
		name string
		slug string
	}{
		{"uppercase", "GOOGLE"},
		{"underscore", "my_provider"},
		{"starts with hyphen", "-bad"},
		{"ends with hyphen", "bad-"},
		{"special characters", "my@provider"},
		{"spaces", "my provider"},
		{"camelCase", "myProvider"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := createTestProvider("Test Provider", tt.slug)
			_, err := repo.CreateProvider(ctx, input)
			if err == nil {
				t.Errorf("expected error for invalid slug %q", tt.slug)
			}
		})
	}
}

func TestSSORepository_CreateProvider_ValidSlugFormats(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	validSlugs := []string{
		"google",
		"my-provider",
		"okta1",
		"provider123",
		"a",
		"ab",
		"a1",
		"1a",
	}

	for i, slug := range validSlugs {
		t.Run(slug, func(t *testing.T) {
			input := createTestProvider("Provider "+slug, slug)
			input.ClientID = "client-" + slug // Make unique
			provider, err := repo.CreateProvider(ctx, input)
			if err != nil {
				t.Errorf("expected valid slug %q to succeed, got error: %v (index %d)", slug, err, i)
			}
			if provider != nil && provider.Slug != slug {
				t.Errorf("expected slug %q, got %q", slug, provider.Slug)
			}
		})
	}
}

func TestSSORepository_CreateProvider_InvalidRole(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	tests := []struct {
		name string
		role string
	}{
		{"superadmin", "superadmin"},
		{"root", "root"},
		{"moderator", "moderator"},
		{"ADMIN uppercase", "ADMIN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := createTestProvider("Test Provider", "test-"+tt.role)
			input.DefaultRole = tt.role
			_, err := repo.CreateProvider(ctx, input)
			if err == nil {
				t.Errorf("expected error for invalid role %q", tt.role)
			}
		})
	}
}

func TestSSORepository_CreateProvider_ValidRoles(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	validRoles := []string{"user", "admin", ""}

	for i, role := range validRoles {
		t.Run("role_"+role, func(t *testing.T) {
			slug := "provider-role-" + role
			if role == "" {
				slug = "provider-role-empty"
			}
			input := createTestProvider("Provider "+slug, slug)
			input.DefaultRole = role
			provider, err := repo.CreateProvider(ctx, input)
			if err != nil {
				t.Errorf("expected valid role %q to succeed, got error: %v (index %d)", role, err, i)
			}
			if provider != nil && provider.DefaultRole != role {
				t.Errorf("expected role %q, got %q", role, provider.DefaultRole)
			}
		})
	}
}

func TestSSORepository_CreateProvider_InvalidColor(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	tests := []struct {
		name  string
		color string
	}{
		{"color name", "red"},
		{"short hex", "#fff"},
		{"no hash", "ffffff"},
		{"invalid chars", "#gggggg"},
		{"too long", "#fffffff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := createTestProvider("Test Provider", "test-color-"+tt.name)
			input.ButtonColor = tt.color
			_, err := repo.CreateProvider(ctx, input)
			if err == nil {
				t.Errorf("expected error for invalid color %q", tt.color)
			}
		})
	}
}

func TestSSORepository_CreateProvider_ValidColors(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	validColors := []string{"#ffffff", "#000000", "#4285F4", "#AABBCC", ""}

	for i, color := range validColors {
		t.Run("color_"+color, func(t *testing.T) {
			// Use simple alphanumeric slug that avoids the # character
			slug := "provider-color-" + string(rune('a'+i))
			input := createTestProvider("Provider "+slug, slug)
			input.ButtonColor = color
			provider, err := repo.CreateProvider(ctx, input)
			if err != nil {
				t.Errorf("expected valid color %q to succeed, got error: %v (index %d)", color, err, i)
			}
			if provider != nil && provider.ButtonColor != color {
				t.Errorf("expected color %q, got %q", color, provider.ButtonColor)
			}
		})
	}
}

func TestSSORepository_CreateProvider_InvalidIconURL(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	tests := []struct {
		name    string
		iconURL string
	}{
		{"javascript scheme", "javascript:alert(1)"},
		{"data scheme", "data:text/html,<script>alert(1)</script>"},
		{"file scheme", "file:///etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := createTestProvider("Test Provider", "test-icon-"+tt.name)
			input.IconURL = tt.iconURL
			_, err := repo.CreateProvider(ctx, input)
			if err == nil {
				t.Errorf("expected error for invalid icon URL %q", tt.iconURL)
			}
		})
	}
}

func TestSSORepository_CreateProvider_ValidIconURLs(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	validURLs := []string{
		"",
		"https://example.com/icon.png",
		"http://example.com/icon.png",
		"/icons/provider.png",
	}

	for i, url := range validURLs {
		t.Run("icon_url_"+url, func(t *testing.T) {
			slug := "provider-icon-" + string(rune('a'+i))
			input := createTestProvider("Provider "+slug, slug)
			input.IconURL = url
			provider, err := repo.CreateProvider(ctx, input)
			if err != nil {
				t.Errorf("expected valid icon URL %q to succeed, got error: %v", url, err)
			}
			if provider != nil && provider.IconURL != url {
				t.Errorf("expected icon URL %q, got %q", url, provider.IconURL)
			}
		})
	}
}

func TestSSORepository_GetProvider_Found(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	created, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider, err := repo.GetProvider(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetProvider failed: %v", err)
	}
	if provider.Name != "Google" {
		t.Errorf("expected name 'Google', got %q", provider.Name)
	}
	if provider.Slug != "google" {
		t.Errorf("expected slug 'google', got %q", provider.Slug)
	}
}

func TestSSORepository_GetProvider_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetProvider(ctx, 99999)
	if err != repository.ErrSSOProviderNotFound {
		t.Errorf("expected ErrSSOProviderNotFound, got %v", err)
	}
}

func TestSSORepository_GetProvider_InvalidID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetProvider(ctx, 0)
	if err == nil {
		t.Error("expected error for invalid ID 0")
	}

	_, err = repo.GetProvider(ctx, -1)
	if err == nil {
		t.Error("expected error for invalid ID -1")
	}
}

func TestSSORepository_GetProviderBySlug_Found(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider, err := repo.GetProviderBySlug(ctx, "google")
	if err != nil {
		t.Fatalf("GetProviderBySlug failed: %v", err)
	}
	if provider.Name != "Google" {
		t.Errorf("expected name 'Google', got %q", provider.Name)
	}
}

func TestSSORepository_GetProviderBySlug_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetProviderBySlug(ctx, "nonexistent")
	if err != repository.ErrSSOProviderNotFound {
		t.Errorf("expected ErrSSOProviderNotFound, got %v", err)
	}
}

func TestSSORepository_GetProviderBySlug_EmptySlug(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetProviderBySlug(ctx, "")
	if err == nil {
		t.Error("expected error for empty slug")
	}
}

func TestSSORepository_GetEnabledProviderBySlug_FoundEnabled(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	input := createTestProvider("Google", "google")
	input.Enabled = true
	_, err := repo.CreateProvider(ctx, input)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	provider, err := repo.GetEnabledProviderBySlug(ctx, "google")
	if err != nil {
		t.Fatalf("GetEnabledProviderBySlug failed: %v", err)
	}
	if provider.Name != "Google" {
		t.Errorf("expected name 'Google', got %q", provider.Name)
	}
	if !provider.Enabled {
		t.Error("expected provider to be enabled")
	}
}

func TestSSORepository_GetEnabledProviderBySlug_FoundDisabled(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	input := createTestProvider("Google", "google")
	input.Enabled = false
	_, err := repo.CreateProvider(ctx, input)
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	_, err = repo.GetEnabledProviderBySlug(ctx, "google")
	if err != repository.ErrSSOProviderDisabled {
		t.Errorf("expected ErrSSOProviderDisabled, got %v", err)
	}
}

func TestSSORepository_GetEnabledProviderBySlug_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetEnabledProviderBySlug(ctx, "nonexistent")
	if err != repository.ErrSSOProviderNotFound {
		t.Errorf("expected ErrSSOProviderNotFound, got %v", err)
	}
}

func TestSSORepository_UpdateProvider_Valid(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	created, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	newName := "Google Auth"
	newEnabled := false
	updated, err := repo.UpdateProvider(ctx, created.ID, &repository.UpdateSSOProviderInput{
		Name:    &newName,
		Enabled: &newEnabled,
	})
	if err != nil {
		t.Fatalf("UpdateProvider failed: %v", err)
	}
	if updated.Name != "Google Auth" {
		t.Errorf("expected name 'Google Auth', got %q", updated.Name)
	}
	if updated.Enabled {
		t.Error("expected provider to be disabled")
	}
}

func TestSSORepository_UpdateProvider_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	newName := "Updated"
	_, err := repo.UpdateProvider(ctx, 99999, &repository.UpdateSSOProviderInput{
		Name: &newName,
	})
	if err != repository.ErrSSOProviderNotFound {
		t.Errorf("expected ErrSSOProviderNotFound, got %v", err)
	}
}

func TestSSORepository_UpdateProvider_InvalidRole(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	created, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	invalidRole := "superadmin"
	_, err = repo.UpdateProvider(ctx, created.ID, &repository.UpdateSSOProviderInput{
		DefaultRole: &invalidRole,
	})
	if err == nil {
		t.Error("expected error for invalid role")
	}
}

func TestSSORepository_UpdateProvider_InvalidColor(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	created, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	invalidColor := "red"
	_, err = repo.UpdateProvider(ctx, created.ID, &repository.UpdateSSOProviderInput{
		ButtonColor: &invalidColor,
	})
	if err == nil {
		t.Error("expected error for invalid color")
	}
}

func TestSSORepository_UpdateProvider_InvalidIconURL(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	created, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	invalidIconURL := "javascript:alert(1)"
	_, err = repo.UpdateProvider(ctx, created.ID, &repository.UpdateSSOProviderInput{
		IconURL: &invalidIconURL,
	})
	if err == nil {
		t.Error("expected error for invalid icon URL")
	}
}

func TestSSORepository_UpdateProvider_NoChanges(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	created, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Update with empty input (no changes)
	updated, err := repo.UpdateProvider(ctx, created.ID, &repository.UpdateSSOProviderInput{})
	if err != nil {
		t.Fatalf("UpdateProvider with no changes failed: %v", err)
	}
	if updated.Name != "Google" {
		t.Errorf("expected name 'Google', got %q", updated.Name)
	}
}

func TestSSORepository_DeleteProvider_Found(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	created, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	err = repo.DeleteProvider(ctx, created.ID)
	if err != nil {
		t.Fatalf("DeleteProvider failed: %v", err)
	}

	// Verify deleted
	_, err = repo.GetProvider(ctx, created.ID)
	if err != repository.ErrSSOProviderNotFound {
		t.Errorf("expected ErrSSOProviderNotFound after deletion, got %v", err)
	}
}

func TestSSORepository_DeleteProvider_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	err := repo.DeleteProvider(ctx, 99999)
	if err != repository.ErrSSOProviderNotFound {
		t.Errorf("expected ErrSSOProviderNotFound, got %v", err)
	}
}

func TestSSORepository_DeleteProvider_InvalidID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	err := repo.DeleteProvider(ctx, 0)
	if err == nil {
		t.Error("expected error for invalid ID 0")
	}
}

func TestSSORepository_DeleteProvider_CascadeDeletesLinksAndStates(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Create provider
	provider, err := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Create SSO link
	_, err = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "ext-123",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	// Create SSO state
	_, err = repo.CreateState(ctx, "state-123", "nonce-123", provider.ID, "/dashboard", "127.0.0.1", nil, time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	// Delete provider (should cascade)
	err = repo.DeleteProvider(ctx, provider.ID)
	if err != nil {
		t.Fatalf("DeleteProvider failed: %v", err)
	}

	// Verify links are deleted
	links, _ := repo.GetLinksByProviderID(ctx, provider.ID)
	if len(links) != 0 {
		t.Errorf("expected 0 links after cascade delete, got %d", len(links))
	}
}

func TestSSORepository_ListProviders_All(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Create providers (enabled and disabled)
	input1 := createTestProvider("Google", "google")
	input1.Enabled = true
	_, _ = repo.CreateProvider(ctx, input1)

	input2 := createTestProvider("Okta", "okta")
	input2.Enabled = false
	_, _ = repo.CreateProvider(ctx, input2)

	input3 := createTestProvider("Azure", "azure")
	input3.Enabled = true
	_, _ = repo.CreateProvider(ctx, input3)

	providers, err := repo.ListProviders(ctx, false)
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}
	if len(providers) != 3 {
		t.Errorf("expected 3 providers, got %d", len(providers))
	}
}

func TestSSORepository_ListProviders_EnabledOnly(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Create providers (enabled and disabled)
	input1 := createTestProvider("Google", "google")
	input1.Enabled = true
	_, _ = repo.CreateProvider(ctx, input1)

	input2 := createTestProvider("Okta", "okta")
	input2.Enabled = false
	_, _ = repo.CreateProvider(ctx, input2)

	input3 := createTestProvider("Azure", "azure")
	input3.Enabled = true
	_, _ = repo.CreateProvider(ctx, input3)

	providers, err := repo.ListProviders(ctx, true)
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}
	if len(providers) != 2 {
		t.Errorf("expected 2 enabled providers, got %d", len(providers))
	}

	// Verify all returned providers are enabled
	for _, p := range providers {
		if !p.Enabled {
			t.Errorf("expected all returned providers to be enabled, got disabled: %s", p.Slug)
		}
	}
}

func TestSSORepository_ListProviders_Empty(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	providers, err := repo.ListProviders(ctx, false)
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}
	// Note: It's acceptable for the slice to be nil when empty
	// Both nil and empty slice have len == 0
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}
}

func TestSSORepository_GetProviderCount(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Initially zero
	count, err := repo.GetProviderCount(ctx)
	if err != nil {
		t.Fatalf("GetProviderCount failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	// Add providers
	_, _ = repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	_, _ = repo.CreateProvider(ctx, createTestProvider("Okta", "okta"))

	count, err = repo.GetProviderCount(ctx)
	if err != nil {
		t.Fatalf("GetProviderCount failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

// ===========================================================================
// User SSO Link Operation Tests
// ===========================================================================

func TestSSORepository_CreateLink_Valid(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Create provider first
	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	link, err := repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:        1,
		ProviderID:    provider.ID,
		ExternalID:    "google-user-123",
		ExternalEmail: "user@gmail.com",
		ExternalName:  "Test User",
	})
	if err != nil {
		t.Fatalf("CreateLink failed: %v", err)
	}
	if link.ID == 0 {
		t.Error("expected link ID to be set")
	}
	if link.ExternalID != "google-user-123" {
		t.Errorf("expected external ID 'google-user-123', got %q", link.ExternalID)
	}
	if link.ExternalEmail != "user@gmail.com" {
		t.Errorf("expected external email 'user@gmail.com', got %q", link.ExternalEmail)
	}
}

func TestSSORepository_CreateLink_Duplicate(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	// Create first link
	_, err := repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "google-user-123",
	})
	if err != nil {
		t.Fatalf("failed to create first link: %v", err)
	}

	// Try to create duplicate
	_, err = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "google-user-123",
	})
	if err != repository.ErrSSOLinkExists {
		t.Errorf("expected ErrSSOLinkExists, got %v", err)
	}
}

func TestSSORepository_CreateLink_InvalidInput(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	tests := []struct {
		name  string
		input *repository.CreateUserSSOLinkInput
	}{
		{"nil input", nil},
		{"invalid user ID", &repository.CreateUserSSOLinkInput{UserID: 0, ProviderID: provider.ID, ExternalID: "ext"}},
		{"invalid provider ID", &repository.CreateUserSSOLinkInput{UserID: 1, ProviderID: 0, ExternalID: "ext"}},
		{"empty external ID", &repository.CreateUserSSOLinkInput{UserID: 1, ProviderID: provider.ID, ExternalID: ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := repo.CreateLink(ctx, tt.input)
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestSSORepository_GetLink_Found(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	created, err := repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "ext-123",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	link, err := repo.GetLink(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetLink failed: %v", err)
	}
	if link.ExternalID != "ext-123" {
		t.Errorf("expected external ID 'ext-123', got %q", link.ExternalID)
	}
}

func TestSSORepository_GetLink_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetLink(ctx, 99999)
	if err != repository.ErrSSOLinkNotFound {
		t.Errorf("expected ErrSSOLinkNotFound, got %v", err)
	}
}

func TestSSORepository_GetLink_InvalidID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetLink(ctx, 0)
	if err == nil {
		t.Error("expected error for invalid ID 0")
	}
}

func TestSSORepository_GetLinkByExternalID_Found(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	_, err := repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "unique-external-id",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	link, err := repo.GetLinkByExternalID(ctx, provider.ID, "unique-external-id")
	if err != nil {
		t.Fatalf("GetLinkByExternalID failed: %v", err)
	}
	if link.ExternalID != "unique-external-id" {
		t.Errorf("expected external ID 'unique-external-id', got %q", link.ExternalID)
	}
	if link.UserID != 1 {
		t.Errorf("expected user ID 1, got %d", link.UserID)
	}
}

func TestSSORepository_GetLinkByExternalID_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	_, err := repo.GetLinkByExternalID(ctx, provider.ID, "nonexistent")
	if err != repository.ErrSSOLinkNotFound {
		t.Errorf("expected ErrSSOLinkNotFound, got %v", err)
	}
}

func TestSSORepository_GetLinkByExternalID_InvalidInput(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetLinkByExternalID(ctx, 0, "ext-id")
	if err == nil {
		t.Error("expected error for invalid provider ID")
	}

	_, err = repo.GetLinkByExternalID(ctx, 1, "")
	if err == nil {
		t.Error("expected error for empty external ID")
	}
}

func TestSSORepository_GetLinksByUserID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Create two providers
	provider1, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))
	provider2, _ := repo.CreateProvider(ctx, createTestProvider("Okta", "okta"))

	// Create links for user 1
	_, _ = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{UserID: 1, ProviderID: provider1.ID, ExternalID: "ext-1"})
	_, _ = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{UserID: 1, ProviderID: provider2.ID, ExternalID: "ext-2"})

	links, err := repo.GetLinksByUserID(ctx, 1)
	if err != nil {
		t.Fatalf("GetLinksByUserID failed: %v", err)
	}
	if len(links) != 2 {
		t.Errorf("expected 2 links, got %d", len(links))
	}
}

func TestSSORepository_UpdateLinkTokens(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	link, err := repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "ext-123",
	})
	if err != nil {
		t.Fatalf("failed to create link: %v", err)
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	err = repo.UpdateLinkTokens(ctx, link.ID, "new-access-token", "new-refresh-token", &expiresAt)
	if err != nil {
		t.Fatalf("UpdateLinkTokens failed: %v", err)
	}

	// Verify update
	updated, _ := repo.GetLink(ctx, link.ID)
	if updated.AccessToken != "new-access-token" {
		t.Errorf("expected access token 'new-access-token', got %q", updated.AccessToken)
	}
	if updated.RefreshToken != "new-refresh-token" {
		t.Errorf("expected refresh token 'new-refresh-token', got %q", updated.RefreshToken)
	}
}

func TestSSORepository_UpdateLinkTokens_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	err := repo.UpdateLinkTokens(ctx, 99999, "token", "refresh", nil)
	if err != repository.ErrSSOLinkNotFound {
		t.Errorf("expected ErrSSOLinkNotFound, got %v", err)
	}
}

func TestSSORepository_UpdateLinkLastLogin(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	link, _ := repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "ext-123",
	})

	err := repo.UpdateLinkLastLogin(ctx, link.ID)
	if err != nil {
		t.Fatalf("UpdateLinkLastLogin failed: %v", err)
	}

	// Verify update
	updated, _ := repo.GetLink(ctx, link.ID)
	if updated.LastLoginAt == nil {
		t.Error("expected last login to be set")
	}
}

func TestSSORepository_DeleteLink(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	link, _ := repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "ext-123",
	})

	err := repo.DeleteLink(ctx, link.ID)
	if err != nil {
		t.Fatalf("DeleteLink failed: %v", err)
	}

	// Verify deleted
	_, err = repo.GetLink(ctx, link.ID)
	if err != repository.ErrSSOLinkNotFound {
		t.Errorf("expected ErrSSOLinkNotFound after deletion, got %v", err)
	}
}

func TestSSORepository_DeleteLink_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	err := repo.DeleteLink(ctx, 99999)
	if err != repository.ErrSSOLinkNotFound {
		t.Errorf("expected ErrSSOLinkNotFound, got %v", err)
	}
}

func TestSSORepository_DeleteLinksByUserID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	// Create multiple links for user 1
	_, _ = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{UserID: 1, ProviderID: provider.ID, ExternalID: "ext-1"})

	err := repo.DeleteLinksByUserID(ctx, 1)
	if err != nil {
		t.Fatalf("DeleteLinksByUserID failed: %v", err)
	}

	links, _ := repo.GetLinksByUserID(ctx, 1)
	if len(links) != 0 {
		t.Errorf("expected 0 links after deletion, got %d", len(links))
	}
}

func TestSSORepository_DeleteLinksByProviderID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	// Create link for the provider
	_, _ = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{UserID: 1, ProviderID: provider.ID, ExternalID: "ext-1"})

	err := repo.DeleteLinksByProviderID(ctx, provider.ID)
	if err != nil {
		t.Fatalf("DeleteLinksByProviderID failed: %v", err)
	}

	links, _ := repo.GetLinksByProviderID(ctx, provider.ID)
	if len(links) != 0 {
		t.Errorf("expected 0 links after deletion, got %d", len(links))
	}
}

func TestSSORepository_DeleteLinksByProviderID_InvalidID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	err := repo.DeleteLinksByProviderID(ctx, 0)
	if err == nil {
		t.Error("expected error for invalid provider ID 0")
	}
}

func TestSSORepository_CountLinksByProviderID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	// Initially zero
	count, err := repo.CountLinksByProviderID(ctx, provider.ID)
	if err != nil {
		t.Fatalf("CountLinksByProviderID failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	// Add a link
	_, _ = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{UserID: 1, ProviderID: provider.ID, ExternalID: "ext-1"})

	count, err = repo.CountLinksByProviderID(ctx, provider.ID)
	if err != nil {
		t.Fatalf("CountLinksByProviderID failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}

func TestSSORepository_GetLinkByUserAndProvider(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	_, _ = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "ext-123",
	})

	link, err := repo.GetLinkByUserAndProvider(ctx, 1, provider.ID)
	if err != nil {
		t.Fatalf("GetLinkByUserAndProvider failed: %v", err)
	}
	if link.ExternalID != "ext-123" {
		t.Errorf("expected external ID 'ext-123', got %q", link.ExternalID)
	}
}

func TestSSORepository_GetLinkByUserAndProvider_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetLinkByUserAndProvider(ctx, 1, 99999)
	if err != repository.ErrSSOLinkNotFound {
		t.Errorf("expected ErrSSOLinkNotFound, got %v", err)
	}
}

// ===========================================================================
// SSO State Operation Tests
// ===========================================================================

func TestSSORepository_CreateState_Valid(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	expiresAt := time.Now().Add(10 * time.Minute)
	state, err := repo.CreateState(ctx, "state-token-123", "nonce-456", provider.ID, "/dashboard", "192.168.1.1", nil, expiresAt)
	if err != nil {
		t.Fatalf("CreateState failed: %v", err)
	}
	if state.ID == 0 {
		t.Error("expected state ID to be set")
	}
	if state.State != "state-token-123" {
		t.Errorf("expected state 'state-token-123', got %q", state.State)
	}
	if state.Nonce != "nonce-456" {
		t.Errorf("expected nonce 'nonce-456', got %q", state.Nonce)
	}
	if state.ReturnURL != "/dashboard" {
		t.Errorf("expected return URL '/dashboard', got %q", state.ReturnURL)
	}
}

func TestSSORepository_CreateState_WithUserID(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	userID := int64(1)
	expiresAt := time.Now().Add(10 * time.Minute)
	state, err := repo.CreateState(ctx, "state-token-123", "nonce-456", provider.ID, "/dashboard", "192.168.1.1", &userID, expiresAt)
	if err != nil {
		t.Fatalf("CreateState failed: %v", err)
	}
	if state.UserID == nil || *state.UserID != 1 {
		t.Error("expected user ID to be set to 1")
	}
}

func TestSSORepository_CreateState_InvalidReturnURL_ExternalURL(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	expiresAt := time.Now().Add(10 * time.Minute)

	// External URLs should be rejected (open redirect prevention)
	invalidURLs := []string{
		"https://evil.com/redirect",
		"http://malicious.com/callback",
		"//evil.com/path",
	}

	for _, url := range invalidURLs {
		t.Run(url, func(t *testing.T) {
			_, err := repo.CreateState(ctx, "state-"+url, "nonce", provider.ID, url, "127.0.0.1", nil, expiresAt)
			if err == nil {
				t.Errorf("expected error for external return URL %q", url)
			}
		})
	}
}

func TestSSORepository_CreateState_InvalidReturnURL_PathTraversal(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	expiresAt := time.Now().Add(10 * time.Minute)

	// Path traversal should be rejected
	_, err := repo.CreateState(ctx, "state-traversal", "nonce", provider.ID, "/dashboard/../../../etc/passwd", "127.0.0.1", nil, expiresAt)
	if err == nil {
		t.Error("expected error for path traversal attempt")
	}
}

func TestSSORepository_CreateState_ValidReturnURLs(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	expiresAt := time.Now().Add(10 * time.Minute)

	validURLs := []string{
		"",
		"/dashboard",
		"/files/upload",
		"/admin/settings",
		"/path?query=value",
	}

	for i, url := range validURLs {
		t.Run("url_"+url, func(t *testing.T) {
			stateToken := "state-" + string(rune('a'+i))
			nonceToken := "nonce-" + string(rune('a'+i))
			state, err := repo.CreateState(ctx, stateToken, nonceToken, provider.ID, url, "127.0.0.1", nil, expiresAt)
			if err != nil {
				t.Errorf("expected valid return URL %q to succeed, got error: %v", url, err)
			}
			if state != nil && state.ReturnURL != url {
				t.Errorf("expected return URL %q, got %q", url, state.ReturnURL)
			}
		})
	}
}

func TestSSORepository_CreateState_InvalidInput(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	expiresAt := time.Now().Add(10 * time.Minute)

	tests := []struct {
		name       string
		state      string
		nonce      string
		providerID int64
	}{
		{"empty state", "", "nonce", provider.ID},
		{"empty nonce", "state", "", provider.ID},
		{"invalid provider ID", "state", "nonce", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := repo.CreateState(ctx, tt.state, tt.nonce, tt.providerID, "/dashboard", "127.0.0.1", nil, expiresAt)
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestSSORepository_GetState_Found(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	expiresAt := time.Now().Add(10 * time.Minute)
	_, err := repo.CreateState(ctx, "state-token-123", "nonce-456", provider.ID, "/dashboard", "192.168.1.1", nil, expiresAt)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}

	state, err := repo.GetState(ctx, "state-token-123")
	if err != nil {
		t.Fatalf("GetState failed: %v", err)
	}
	if state.Nonce != "nonce-456" {
		t.Errorf("expected nonce 'nonce-456', got %q", state.Nonce)
	}
	if state.ProviderID != provider.ID {
		t.Errorf("expected provider ID %d, got %d", provider.ID, state.ProviderID)
	}
}

func TestSSORepository_GetState_NotFound(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetState(ctx, "nonexistent-state")
	if err != repository.ErrSSOStateNotFound {
		t.Errorf("expected ErrSSOStateNotFound, got %v", err)
	}
}

func TestSSORepository_GetState_Expired(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	// Create state that has already expired
	expiresAt := time.Now().Add(-10 * time.Minute)
	// Directly insert into database to bypass any validation
	_, err := db.Exec(`INSERT INTO sso_states (state, nonce, provider_id, return_url, created_ip, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		"expired-state", "nonce", provider.ID, "/dashboard", "127.0.0.1", expiresAt)
	if err != nil {
		t.Fatalf("failed to insert expired state: %v", err)
	}

	_, err = repo.GetState(ctx, "expired-state")
	if err != repository.ErrSSOStateExpired {
		t.Errorf("expected ErrSSOStateExpired, got %v", err)
	}
}

func TestSSORepository_GetState_InvalidInput(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	_, err := repo.GetState(ctx, "")
	if err == nil {
		t.Error("expected error for empty state")
	}
}

func TestSSORepository_DeleteState(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	expiresAt := time.Now().Add(10 * time.Minute)
	_, _ = repo.CreateState(ctx, "state-to-delete", "nonce", provider.ID, "/dashboard", "127.0.0.1", nil, expiresAt)

	err := repo.DeleteState(ctx, "state-to-delete")
	if err != nil {
		t.Fatalf("DeleteState failed: %v", err)
	}

	// Verify deleted
	_, err = repo.GetState(ctx, "state-to-delete")
	if err != repository.ErrSSOStateNotFound {
		t.Errorf("expected ErrSSOStateNotFound after deletion, got %v", err)
	}
}

func TestSSORepository_DeleteState_InvalidInput(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	err := repo.DeleteState(ctx, "")
	if err == nil {
		t.Error("expected error for empty state")
	}
}

func TestSSORepository_CleanupExpiredStates(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	// Create expired states directly in DB
	expiredTime := time.Now().Add(-10 * time.Minute).Format("2006-01-02 15:04:05")
	validTime := time.Now().Add(10 * time.Minute).Format("2006-01-02 15:04:05")

	_, _ = db.Exec(`INSERT INTO sso_states (state, nonce, provider_id, return_url, created_ip, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		"expired-1", "nonce1", provider.ID, "/", "127.0.0.1", expiredTime)
	_, _ = db.Exec(`INSERT INTO sso_states (state, nonce, provider_id, return_url, created_ip, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		"expired-2", "nonce2", provider.ID, "/", "127.0.0.1", expiredTime)
	_, _ = db.Exec(`INSERT INTO sso_states (state, nonce, provider_id, return_url, created_ip, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		"valid-1", "nonce3", provider.ID, "/", "127.0.0.1", validTime)

	deleted, err := repo.CleanupExpiredStates(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredStates failed: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted states, got %d", deleted)
	}

	// Verify valid state still exists
	state, err := repo.GetState(ctx, "valid-1")
	if err != nil {
		t.Errorf("valid state should still exist: %v", err)
	}
	if state != nil && state.State != "valid-1" {
		t.Error("expected valid state to remain")
	}
}

// ===========================================================================
// Validation Tests (Table-Driven)
// ===========================================================================

func TestSSORepository_SlugValidation(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	tests := []struct {
		slug    string
		valid   bool
		comment string
	}{
		{"google", true, "simple lowercase"},
		{"my-provider", true, "with hyphen"},
		{"okta1", true, "with number"},
		{"a", true, "single char"},
		{"a1", true, "char and number"},
		{"1", true, "single digit"},
		{"GOOGLE", false, "uppercase"},
		{"my_provider", false, "underscore"},
		{"-bad", false, "starts with hyphen"},
		{"bad-", false, "ends with hyphen"},
		{"my--provider", true, "double hyphen is valid"},
		{"My-Provider", false, "mixed case"},
		{"provider@123", false, "special char"},
		{"", false, "empty string"},
	}

	for i, tt := range tests {
		t.Run(tt.slug+"_"+tt.comment, func(t *testing.T) {
			slug := tt.slug
			if slug == "" {
				slug = "test-empty-" + string(rune('a'+i))
			}
			input := createTestProvider("Provider "+slug, tt.slug)
			_, err := repo.CreateProvider(ctx, input)
			if tt.valid && err != nil {
				t.Errorf("slug %q should be valid, got error: %v", tt.slug, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("slug %q should be invalid, but succeeded", tt.slug)
			}
		})
	}
}

func TestSSORepository_ReturnURLValidation(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	tests := []struct {
		url     string
		valid   bool
		comment string
	}{
		{"/dashboard", true, "relative path"},
		{"/files/upload", true, "nested path"},
		{"/path?query=value", true, "with query string"},
		{"", true, "empty string"},
		{"https://evil.com", false, "external https"},
		{"http://malicious.com/redirect", false, "external http"},
		{"//evil.com/path", false, "protocol-relative"},
		{"/dashboard/../../../etc/passwd", false, "path traversal"},
		{"ftp://server.com/file", false, "ftp scheme"},
	}

	expiresAt := time.Now().Add(10 * time.Minute)

	for i, tt := range tests {
		t.Run(tt.url+"_"+tt.comment, func(t *testing.T) {
			stateToken := "state-return-" + string(rune('a'+i))
			nonceToken := "nonce-return-" + string(rune('a'+i))
			_, err := repo.CreateState(ctx, stateToken, nonceToken, provider.ID, tt.url, "127.0.0.1", nil, expiresAt)
			if tt.valid && err != nil {
				t.Errorf("return URL %q should be valid, got error: %v", tt.url, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("return URL %q should be invalid, but succeeded", tt.url)
			}
		})
	}
}

func TestSSORepository_DefaultRoleValidation(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	tests := []struct {
		role    string
		valid   bool
		comment string
	}{
		{"user", true, "standard user role"},
		{"admin", true, "admin role"},
		{"", true, "empty string"},
		{"superadmin", false, "invalid superadmin"},
		{"root", false, "invalid root"},
		{"moderator", false, "invalid moderator"},
		{"USER", false, "uppercase user"},
		{"ADMIN", false, "uppercase admin"},
	}

	for i, tt := range tests {
		t.Run(tt.role+"_"+tt.comment, func(t *testing.T) {
			slug := "provider-role-" + string(rune('a'+i))
			input := createTestProvider("Provider "+slug, slug)
			input.DefaultRole = tt.role
			_, err := repo.CreateProvider(ctx, input)
			if tt.valid && err != nil {
				t.Errorf("role %q should be valid, got error: %v", tt.role, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("role %q should be invalid, but succeeded", tt.role)
			}
		})
	}
}

func TestSSORepository_IconURLValidation(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	tests := []struct {
		iconURL string
		valid   bool
		comment string
	}{
		{"https://example.com/icon.png", true, "https URL"},
		{"http://example.com/icon.png", true, "http URL"},
		{"", true, "empty string"},
		{"/icons/provider.png", true, "relative path"},
		{"javascript:alert(1)", false, "javascript scheme"},
		{"data:text/html,<script>alert(1)</script>", false, "data scheme"},
		{"file:///etc/passwd", false, "file scheme"},
	}

	for i, tt := range tests {
		t.Run(tt.iconURL+"_"+tt.comment, func(t *testing.T) {
			slug := "provider-icon-" + string(rune('a'+i))
			input := createTestProvider("Provider "+slug, slug)
			input.IconURL = tt.iconURL
			_, err := repo.CreateProvider(ctx, input)
			if tt.valid && err != nil {
				t.Errorf("icon URL %q should be valid, got error: %v", tt.iconURL, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("icon URL %q should be invalid, but succeeded", tt.iconURL)
			}
		})
	}
}

func TestSSORepository_ButtonColorValidation(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	tests := []struct {
		color   string
		valid   bool
		comment string
	}{
		{"#ffffff", true, "lowercase hex"},
		{"#000000", true, "black"},
		{"#FFFFFF", true, "uppercase hex"},
		{"#4285F4", true, "mixed case hex"},
		{"", true, "empty string"},
		{"red", false, "color name"},
		{"#fff", false, "short hex"},
		{"ffffff", false, "no hash"},
		{"#gggggg", false, "invalid hex chars"},
		{"#fffffff", false, "too long"},
		{"#12345", false, "too short"},
	}

	for i, tt := range tests {
		t.Run(tt.color+"_"+tt.comment, func(t *testing.T) {
			slug := "provider-color-" + string(rune('a'+i))
			input := createTestProvider("Provider "+slug, slug)
			input.ButtonColor = tt.color
			_, err := repo.CreateProvider(ctx, input)
			if tt.valid && err != nil {
				t.Errorf("color %q should be valid, got error: %v", tt.color, err)
			}
			if !tt.valid && err == nil {
				t.Errorf("color %q should be invalid, but succeeded", tt.color)
			}
		})
	}
}

// ===========================================================================
// Interface Implementation Test
// ===========================================================================

func TestSSORepository_ImplementsInterface(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	var _ repository.SSORepository = NewSSORepository(db)
}

// ===========================================================================
// Edge Case Tests
// ===========================================================================

func TestSSORepository_ListProvidersWithStats(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Create provider with links
	provider, _ := repo.CreateProvider(ctx, createTestProvider("Google", "google"))

	// Create links
	_, _ = repo.CreateLink(ctx, &repository.CreateUserSSOLinkInput{
		UserID:     1,
		ProviderID: provider.ID,
		ExternalID: "ext-1",
	})

	stats, err := repo.ListProvidersWithStats(ctx)
	if err != nil {
		t.Fatalf("ListProvidersWithStats failed: %v", err)
	}
	if len(stats) != 1 {
		t.Errorf("expected 1 provider, got %d", len(stats))
	}
	if stats[0].LinkedUsersCount != 1 {
		t.Errorf("expected 1 linked user, got %d", stats[0].LinkedUsersCount)
	}
}

func TestSSORepository_MultipleProviders(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Create multiple providers
	for i := 0; i < 5; i++ {
		slug := "provider-" + string(rune('a'+i))
		input := createTestProvider("Provider "+slug, slug)
		input.DisplayOrder = i
		_, err := repo.CreateProvider(ctx, input)
		if err != nil {
			t.Fatalf("failed to create provider %d: %v", i, err)
		}
	}

	providers, err := repo.ListProviders(ctx, false)
	if err != nil {
		t.Fatalf("ListProviders failed: %v", err)
	}
	if len(providers) != 5 {
		t.Errorf("expected 5 providers, got %d", len(providers))
	}

	// Verify ordering by display_order
	for i, p := range providers {
		if p.DisplayOrder != i {
			t.Errorf("expected display order %d, got %d for provider %s", i, p.DisplayOrder, p.Slug)
		}
	}
}

func TestSSORepository_ProviderTypeOIDC(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	input := createTestProvider("OIDC Provider", "oidc-provider")
	input.Type = repository.SSOProviderTypeOIDC

	provider, err := repo.CreateProvider(ctx, input)
	if err != nil {
		t.Fatalf("CreateProvider failed: %v", err)
	}
	if provider.Type != repository.SSOProviderTypeOIDC {
		t.Errorf("expected type 'oidc', got %q", provider.Type)
	}
}

func TestSSORepository_ProviderTypeSAML(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	input := createTestProvider("SAML Provider", "saml-provider")
	input.Type = repository.SSOProviderTypeSAML

	provider, err := repo.CreateProvider(ctx, input)
	if err != nil {
		t.Fatalf("CreateProvider failed: %v", err)
	}
	if provider.Type != repository.SSOProviderTypeSAML {
		t.Errorf("expected type 'saml', got %q", provider.Type)
	}
}

func TestSSORepository_ProviderTypeInvalid(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	input := createTestProvider("Invalid Provider", "invalid-provider")
	input.Type = "invalid"

	_, err := repo.CreateProvider(ctx, input)
	if err == nil {
		t.Error("expected error for invalid provider type")
	}
}

func TestSSORepository_UpdateProvider_AllFields(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	created, err := repo.CreateProvider(ctx, createTestProvider("Original", "original"))
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	// Update all fields
	newName := "Updated Name"
	newEnabled := false
	newClientID := "new-client-id"
	newIssuerURL := "https://new-issuer.com"
	newScopes := "openid email"
	newAutoProvision := true
	newDefaultRole := "admin"
	newIconURL := "https://example.com/new-icon.png"
	newButtonColor := "#ff0000"
	newButtonTextColor := "#ffffff"
	newDisplayOrder := 99

	updated, err := repo.UpdateProvider(ctx, created.ID, &repository.UpdateSSOProviderInput{
		Name:            &newName,
		Enabled:         &newEnabled,
		ClientID:        &newClientID,
		IssuerURL:       &newIssuerURL,
		Scopes:          &newScopes,
		AutoProvision:   &newAutoProvision,
		DefaultRole:     &newDefaultRole,
		IconURL:         &newIconURL,
		ButtonColor:     &newButtonColor,
		ButtonTextColor: &newButtonTextColor,
		DisplayOrder:    &newDisplayOrder,
	})
	if err != nil {
		t.Fatalf("UpdateProvider failed: %v", err)
	}

	if updated.Name != newName {
		t.Errorf("expected name %q, got %q", newName, updated.Name)
	}
	if updated.Enabled != newEnabled {
		t.Errorf("expected enabled %v, got %v", newEnabled, updated.Enabled)
	}
	if updated.ClientID != newClientID {
		t.Errorf("expected client ID %q, got %q", newClientID, updated.ClientID)
	}
	if updated.IssuerURL != newIssuerURL {
		t.Errorf("expected issuer URL %q, got %q", newIssuerURL, updated.IssuerURL)
	}
	if updated.Scopes != newScopes {
		t.Errorf("expected scopes %q, got %q", newScopes, updated.Scopes)
	}
	if updated.AutoProvision != newAutoProvision {
		t.Errorf("expected auto provision %v, got %v", newAutoProvision, updated.AutoProvision)
	}
	if updated.DefaultRole != newDefaultRole {
		t.Errorf("expected default role %q, got %q", newDefaultRole, updated.DefaultRole)
	}
	if updated.IconURL != newIconURL {
		t.Errorf("expected icon URL %q, got %q", newIconURL, updated.IconURL)
	}
	if updated.ButtonColor != newButtonColor {
		t.Errorf("expected button color %q, got %q", newButtonColor, updated.ButtonColor)
	}
	if updated.ButtonTextColor != newButtonTextColor {
		t.Errorf("expected button text color %q, got %q", newButtonTextColor, updated.ButtonTextColor)
	}
	if updated.DisplayOrder != newDisplayOrder {
		t.Errorf("expected display order %d, got %d", newDisplayOrder, updated.DisplayOrder)
	}
}

func TestSSORepository_FindUserByExternalEmail(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Test finding existing user
	userIDs, err := repo.FindUserByExternalEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("FindUserByExternalEmail failed: %v", err)
	}
	if len(userIDs) != 1 {
		t.Errorf("expected 1 user, got %d", len(userIDs))
	}
	if userIDs[0] != 1 {
		t.Errorf("expected user ID 1, got %d", userIDs[0])
	}

	// Test non-existent email
	userIDs, err = repo.FindUserByExternalEmail(ctx, "nonexistent@example.com")
	if err != nil {
		t.Fatalf("FindUserByExternalEmail failed: %v", err)
	}
	if len(userIDs) != 0 {
		t.Errorf("expected 0 users, got %d", len(userIDs))
	}

	// Test empty email
	userIDs, err = repo.FindUserByExternalEmail(ctx, "")
	if err != nil {
		t.Fatalf("FindUserByExternalEmail failed: %v", err)
	}
	if userIDs != nil && len(userIDs) != 0 {
		t.Errorf("expected nil or empty slice, got %v", userIDs)
	}
}

func TestSSORepository_FindUserByExternalEmail_CaseInsensitive(t *testing.T) {
	db := setupSSOTestDB(t)
	defer db.Close()

	repo := NewSSORepository(db)
	ctx := context.Background()

	// Test case insensitivity
	variations := []string{
		"test@example.com",
		"TEST@EXAMPLE.COM",
		"Test@Example.Com",
	}

	for _, email := range variations {
		t.Run(email, func(t *testing.T) {
			userIDs, err := repo.FindUserByExternalEmail(ctx, email)
			if err != nil {
				t.Fatalf("FindUserByExternalEmail failed: %v", err)
			}
			if len(userIDs) != 1 {
				t.Errorf("expected 1 user for email %q, got %d", email, len(userIDs))
			}
		})
	}
}
