package postgres

import (
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/repository"
)

func TestBuildConnectionString(t *testing.T) {
	tests := []struct {
		name            string
		cfg             *config.PostgreSQLConfig
		expectedParts   []string
		unexpectedParts []string
	}{
		{
			name: "basic configuration",
			cfg: &config.PostgreSQLConfig{
				Host:     "localhost",
				Port:     5432,
				User:     "testuser",
				Password: "testpass",
				Database: "testdb",
				SSLMode:  "disable",
			},
			expectedParts: []string{
				"postgres://",
				"testuser:",
				"testpass@",
				"localhost:5432",
				"/testdb",
				"sslmode=disable",
			},
		},
		{
			name: "default SSL mode",
			cfg: &config.PostgreSQLConfig{
				Host:     "localhost",
				Port:     5432,
				User:     "user",
				Password: "pass",
				Database: "db",
				SSLMode:  "", // Should default to prefer
			},
			expectedParts: []string{
				"sslmode=prefer",
			},
		},
		{
			name: "with special characters in password",
			cfg: &config.PostgreSQLConfig{
				Host:     "localhost",
				Port:     5432,
				User:     "user",
				Password: "pass@word:123/test",
				Database: "db",
				SSLMode:  "require",
			},
			expectedParts: []string{
				"postgres://",
				"sslmode=require",
			},
			// The @ and : in password should be URL-encoded, not appear as-is
			unexpectedParts: []string{
				"pass@word:123/test@",
			},
		},
		{
			name: "with additional options",
			cfg: &config.PostgreSQLConfig{
				Host:     "localhost",
				Port:     5432,
				User:     "user",
				Password: "pass",
				Database: "db",
				SSLMode:  "disable",
				Options:  "connect_timeout=10&application_name=safeshare",
			},
			expectedParts: []string{
				"sslmode=disable",
				"connect_timeout=10",
				"application_name=safeshare",
			},
		},
		{
			name: "non-standard port",
			cfg: &config.PostgreSQLConfig{
				Host:     "db.example.com",
				Port:     5433,
				User:     "admin",
				Password: "secret",
				Database: "production",
				SSLMode:  "require",
			},
			expectedParts: []string{
				"db.example.com:5433",
				"/production",
				"sslmode=require",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildConnectionString(tt.cfg)

			for _, part := range tt.expectedParts {
				if !strings.Contains(result, part) {
					t.Errorf("buildConnectionString() = %q, want to contain %q", result, part)
				}
			}

			for _, part := range tt.unexpectedParts {
				if strings.Contains(result, part) {
					t.Errorf("buildConnectionString() = %q, should not contain %q", result, part)
				}
			}
		})
	}
}

func TestNewRepositoriesWithPool_NilPool(t *testing.T) {
	repos, err := NewRepositoriesWithPool(nil)

	if err != repository.ErrNilDatabase {
		t.Errorf("NewRepositoriesWithPool(nil) error = %v, want %v", err, repository.ErrNilDatabase)
	}
	if repos != nil {
		t.Error("NewRepositoriesWithPool(nil) should return nil repos")
	}
}

// Note: NewRepositories and NewRepositoriesWithPool with valid pool
// require an actual PostgreSQL connection and are tested via integration tests.
