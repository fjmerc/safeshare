package sqlite

import (
	"testing"

	"github.com/fjmerc/safeshare/internal/repository"
)

func TestNewRepositories_Success(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repos, err := NewRepositories(nil, db)
	if err != nil {
		t.Fatalf("NewRepositories() error = %v", err)
	}

	// Verify all repositories are created
	if repos.Files == nil {
		t.Error("Files repository is nil")
	}
	if repos.Users == nil {
		t.Error("Users repository is nil")
	}
	if repos.Admin == nil {
		t.Error("Admin repository is nil")
	}
	if repos.Settings == nil {
		t.Error("Settings repository is nil")
	}
	if repos.PartialUploads == nil {
		t.Error("PartialUploads repository is nil")
	}
	if repos.Webhooks == nil {
		t.Error("Webhooks repository is nil")
	}
	if repos.APITokens == nil {
		t.Error("APITokens repository is nil")
	}
}

func TestNewRepositories_NilDatabase(t *testing.T) {
	repos, err := NewRepositories(nil, nil)
	if err == nil {
		t.Fatal("NewRepositories() expected error for nil database, got nil")
	}
	if err != repository.ErrNilDatabase {
		t.Errorf("NewRepositories() error = %v, want %v", err, repository.ErrNilDatabase)
	}
	if repos != nil {
		t.Error("NewRepositories() expected nil repos for nil database")
	}
}

func TestNewRepositories_RepositoriesImplementInterfaces(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	repos, err := NewRepositories(nil, db)
	if err != nil {
		t.Fatalf("NewRepositories() error = %v", err)
	}

	// Type assertions to verify interface implementation
	var _ repository.FileRepository = repos.Files
	var _ repository.UserRepository = repos.Users
	var _ repository.AdminRepository = repos.Admin
	var _ repository.SettingsRepository = repos.Settings
	var _ repository.PartialUploadRepository = repos.PartialUploads
	var _ repository.WebhookRepository = repos.Webhooks
	var _ repository.APITokenRepository = repos.APITokens
}
