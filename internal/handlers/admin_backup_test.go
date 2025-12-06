package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/fjmerc/safeshare/internal/backup"
	"github.com/fjmerc/safeshare/internal/config"

	_ "modernc.org/sqlite"
)

// createTestBackupDatabase creates a test SQLite database for backup tests
func createTestBackupDatabase(t *testing.T, dbPath string) {
	t.Helper()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer db.Close()

	schema := `
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE TABLE IF NOT EXISTS files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			claim_code TEXT UNIQUE NOT NULL,
			original_filename TEXT NOT NULL,
			stored_filename TEXT NOT NULL,
			file_size INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		CREATE TABLE IF NOT EXISTS admin_credentials (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL,
			password_hash TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS blocked_ips (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			reason TEXT
		);
		
		CREATE TABLE IF NOT EXISTS webhook_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			url TEXT NOT NULL,
			events TEXT NOT NULL
		);
		
		CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL
		);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	// Insert sample data
	_, err = db.Exec(`INSERT INTO settings (key, value) VALUES ('max_file_size', '104857600')`)
	if err != nil {
		t.Fatalf("Failed to insert settings: %v", err)
	}

	_, err = db.Exec(`INSERT INTO users (username, email) VALUES ('testuser', 'test@example.com')`)
	if err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	_, err = db.Exec(`INSERT INTO files (claim_code, original_filename, stored_filename, file_size) VALUES ('ABC123', 'test.txt', 'uuid-123', 1024)`)
	if err != nil {
		t.Fatalf("Failed to insert file: %v", err)
	}
}

// createTestBackupUploads creates test upload files
func createTestBackupUploads(t *testing.T, uploadsDir string) {
	t.Helper()

	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("Failed to create uploads dir: %v", err)
	}

	testFiles := map[string]string{
		"uuid-123": "test file content 1",
		"uuid-456": "test file content 2",
	}

	for name, content := range testFiles {
		filePath := filepath.Join(uploadsDir, name)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
	}
}

func TestAdminListBackupsHandler(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	backupDir := filepath.Join(tmpDir, "backups")

	// Create test database
	createTestBackupDatabase(t, dbPath)

	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{
		DBPath:    dbPath,
		DataDir:   tmpDir,
		BackupDir: backupDir,
	}

	t.Run("empty backup directory", func(t *testing.T) {
		handler := AdminListBackupsHandler(db, cfg)
		req := httptest.NewRequest(http.MethodGet, "/api/admin/backups", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var response map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		backups, ok := response["backups"].([]interface{})
		if !ok {
			t.Fatal("Expected backups array in response")
		}

		if len(backups) != 0 {
			t.Errorf("Expected 0 backups, got %d", len(backups))
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		handler := AdminListBackupsHandler(db, cfg)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})

	t.Run("with backups", func(t *testing.T) {
		// Create a backup first
		uploadsDir := filepath.Join(tmpDir, "uploads")
		createTestBackupUploads(t, uploadsDir)
		os.MkdirAll(backupDir, 0755)

		opts := backup.CreateOptions{
			Mode:             backup.ModeDatabase,
			DBPath:           dbPath,
			UploadsDir:       uploadsDir,
			OutputDir:        backupDir,
			SafeShareVersion: "1.4.1",
		}
		_, err := backup.Create(opts)
		if err != nil {
			t.Fatalf("Failed to create backup: %v", err)
		}

		handler := AdminListBackupsHandler(db, cfg)
		req := httptest.NewRequest(http.MethodGet, "/api/admin/backups", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var response map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		backups, ok := response["backups"].([]interface{})
		if !ok {
			t.Fatal("Expected backups array in response")
		}

		if len(backups) == 0 {
			t.Error("Expected at least 1 backup")
		}
	})
}

func TestAdminCreateBackupHandler(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	backupDir := filepath.Join(tmpDir, "backups")
	uploadsDir := filepath.Join(tmpDir, "uploads")

	// Create test data
	createTestBackupDatabase(t, dbPath)
	createTestBackupUploads(t, uploadsDir)

	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{
		DBPath:    dbPath,
		DataDir:   tmpDir,
		BackupDir: backupDir,
		UploadDir: uploadsDir,
		Version:   "1.4.1",
	}

	t.Run("create database backup", func(t *testing.T) {
		handler := AdminCreateBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"mode":"database"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/create", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}

		var response map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response["success"] != true {
			t.Errorf("Expected success=true, got %v", response["success"])
		}
	})

	t.Run("create full backup", func(t *testing.T) {
		handler := AdminCreateBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"mode":"full"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/create", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
	})

	t.Run("create config backup", func(t *testing.T) {
		handler := AdminCreateBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"mode":"config"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/create", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		handler := AdminCreateBackupHandler(db, cfg)
		req := httptest.NewRequest(http.MethodGet, "/api/admin/backups/create", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})

	t.Run("invalid mode", func(t *testing.T) {
		handler := AdminCreateBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"mode":"invalid"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/create", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		handler := AdminCreateBackupHandler(db, cfg)
		body := bytes.NewBufferString(`not valid json`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/create", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})
}

func TestAdminVerifyBackupHandler(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	backupDir := filepath.Join(tmpDir, "backups")
	uploadsDir := filepath.Join(tmpDir, "uploads")

	// Create test data
	createTestBackupDatabase(t, dbPath)
	createTestBackupUploads(t, uploadsDir)
	os.MkdirAll(backupDir, 0755)

	// Create a backup to verify
	opts := backup.CreateOptions{
		Mode:             backup.ModeDatabase,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        backupDir,
		SafeShareVersion: "1.4.1",
	}
	backupResult, err := backup.Create(opts)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{
		DBPath:    dbPath,
		DataDir:   tmpDir,
		BackupDir: backupDir,
	}

	t.Run("verify valid backup by path", func(t *testing.T) {
		handler := AdminVerifyBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"backup_path":"` + backupResult.BackupPath + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/verify", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}

		var response map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response["valid"] != true {
			t.Errorf("Expected valid=true, got %v", response["valid"])
		}
	})

	t.Run("verify by filename", func(t *testing.T) {
		handler := AdminVerifyBackupHandler(db, cfg)
		filename := filepath.Base(backupResult.BackupPath)
		body := bytes.NewBufferString(`{"filename":"` + filename + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/verify", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		handler := AdminVerifyBackupHandler(db, cfg)
		req := httptest.NewRequest(http.MethodGet, "/api/admin/backups/verify", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})

	t.Run("missing path", func(t *testing.T) {
		handler := AdminVerifyBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/verify", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	t.Run("path traversal attempt", func(t *testing.T) {
		handler := AdminVerifyBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"backup_path":"../../../etc/passwd"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/verify", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
	})
}

func TestAdminRestoreBackupHandler(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	backupDir := filepath.Join(tmpDir, "backups")
	uploadsDir := filepath.Join(tmpDir, "uploads")

	// Create test data
	createTestBackupDatabase(t, dbPath)
	createTestBackupUploads(t, uploadsDir)
	os.MkdirAll(backupDir, 0755)

	// Create a backup to restore
	opts := backup.CreateOptions{
		Mode:             backup.ModeDatabase,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        backupDir,
		SafeShareVersion: "1.4.1",
	}
	backupResult, err := backup.Create(opts)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Use a different restore path
	restoreDBPath := filepath.Join(tmpDir, "restored.db")

	cfg := &config.Config{
		DBPath:    restoreDBPath,
		DataDir:   tmpDir,
		BackupDir: backupDir,
		UploadDir: uploadsDir,
	}

	t.Run("dry run restore", func(t *testing.T) {
		handler := AdminRestoreBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"backup_path":"` + backupResult.BackupPath + `","dry_run":true}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/restore", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}

		var response map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response["dry_run"] != true {
			t.Errorf("Expected dry_run=true, got %v", response["dry_run"])
		}
	})

	t.Run("actual restore with force", func(t *testing.T) {
		handler := AdminRestoreBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"backup_path":"` + backupResult.BackupPath + `","force":true,"handle_orphans":"keep"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/restore", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		handler := AdminRestoreBackupHandler(db, cfg)
		req := httptest.NewRequest(http.MethodGet, "/api/admin/backups/restore", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})

	t.Run("missing path", func(t *testing.T) {
		handler := AdminRestoreBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/restore", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	t.Run("invalid orphan handling", func(t *testing.T) {
		handler := AdminRestoreBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"backup_path":"` + backupResult.BackupPath + `","handle_orphans":"invalid"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/restore", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	t.Run("path traversal attempt", func(t *testing.T) {
		handler := AdminRestoreBackupHandler(db, cfg)
		body := bytes.NewBufferString(`{"backup_path":"../../../etc/passwd"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/admin/backups/restore", body)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
	})
}

func TestAdminDeleteBackupHandler(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "safeshare.db")
	backupDir := filepath.Join(tmpDir, "backups")
	uploadsDir := filepath.Join(tmpDir, "uploads")

	// Create test data
	createTestBackupDatabase(t, dbPath)
	createTestBackupUploads(t, uploadsDir)
	os.MkdirAll(backupDir, 0755)

	// Create a backup to delete
	opts := backup.CreateOptions{
		Mode:             backup.ModeDatabase,
		DBPath:           dbPath,
		UploadsDir:       uploadsDir,
		OutputDir:        backupDir,
		SafeShareVersion: "1.4.1",
	}
	backupResult, err := backup.Create(opts)
	if err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{
		DBPath:    dbPath,
		DataDir:   tmpDir,
		BackupDir: backupDir,
	}

	t.Run("delete backup by query param", func(t *testing.T) {
		handler := AdminDeleteBackupHandler(db, cfg)
		filename := filepath.Base(backupResult.BackupPath)
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/backups?filename="+filename, nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		}

		var response map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if response["success"] != true {
			t.Errorf("Expected success=true, got %v", response["success"])
		}

		// Verify backup was deleted
		if _, err := os.Stat(backupResult.BackupPath); !os.IsNotExist(err) {
			t.Error("Backup should have been deleted")
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		handler := AdminDeleteBackupHandler(db, cfg)
		req := httptest.NewRequest(http.MethodGet, "/api/admin/backups", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})

	t.Run("missing filename", func(t *testing.T) {
		handler := AdminDeleteBackupHandler(db, cfg)
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/backups", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	t.Run("nonexistent backup", func(t *testing.T) {
		handler := AdminDeleteBackupHandler(db, cfg)
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/backups?filename=nonexistent", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
		}
	})

	t.Run("path traversal attempt", func(t *testing.T) {
		handler := AdminDeleteBackupHandler(db, cfg)
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/backups?filename=../../../etc/passwd", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
	})
}

func TestIsSubPath(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		child  string
		want   bool
	}{
		{
			name:   "valid subpath",
			parent: "/app/backups",
			child:  "/app/backups/backup-2024",
			want:   true,
		},
		{
			name:   "same path",
			parent: "/app/backups",
			child:  "/app/backups",
			want:   false,
		},
		{
			name:   "parent of parent",
			parent: "/app/backups",
			child:  "/app",
			want:   false,
		},
		{
			name:   "sibling path",
			parent: "/app/backups",
			child:  "/app/uploads/file",
			want:   false,
		},
		{
			name:   "path traversal",
			parent: "/app/backups",
			child:  "/app/backups/../uploads/file",
			want:   false,
		},
		{
			name:   "nested subpath",
			parent: "/app/backups",
			child:  "/app/backups/2024/01/backup",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSubPath(tt.parent, tt.child)
			if got != tt.want {
				t.Errorf("isSubPath(%q, %q) = %v, want %v", tt.parent, tt.child, got, tt.want)
			}
		})
	}
}
