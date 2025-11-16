package metrics

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite" // SQLite driver
)

func setupTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	// Create temp database file
	dbFile := "/tmp/test-metrics-" + t.Name() + ".db"

	db, err := sql.Open("sqlite", dbFile)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create files table
	_, err = db.Exec(`
		CREATE TABLE files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			claim_code TEXT UNIQUE NOT NULL,
			original_filename TEXT NOT NULL,
			stored_filename TEXT NOT NULL,
			file_size INTEGER NOT NULL,
			mime_type TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			download_count INTEGER DEFAULT 0,
			max_downloads INTEGER,
			uploader_ip TEXT NOT NULL,
			password_hash TEXT,
			user_id INTEGER,
			sha256_hash TEXT
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create files table: %v", err)
	}

	// Create partial_uploads table
	_, err = db.Exec(`
		CREATE TABLE partial_uploads (
			upload_id TEXT PRIMARY KEY,
			user_id INTEGER,
			filename TEXT NOT NULL,
			total_size INTEGER NOT NULL,
			chunk_size INTEGER NOT NULL,
			total_chunks INTEGER NOT NULL,
			chunks_received INTEGER DEFAULT 0,
			received_bytes INTEGER DEFAULT 0,
			expires_in_hours INTEGER NOT NULL,
			max_downloads INTEGER NOT NULL,
			password_hash TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			completed BOOLEAN DEFAULT 0,
			claim_code TEXT
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create partial_uploads table: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.Remove(dbFile)
	}

	return db, cleanup
}

func TestNewDatabaseMetricsCollector(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	collector := NewDatabaseMetricsCollector(db, 100.0) // 100 GB quota
	if collector == nil {
		t.Fatal("Expected non-nil collector")
	}

	if collector.db != db {
		t.Error("Collector db not set correctly")
	}

	if collector.quotaLimitGB != 100.0 {
		t.Errorf("Expected quota 100.0, got %f", collector.quotaLimitGB)
	}
}

func TestDatabaseMetricsCollector_EmptyDatabase(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	_ = NewDatabaseMetricsCollector(db, 100.0)

	// Test the SQL queries work correctly on empty database
	var storageUsed int64
	var fileCount int64
	err := db.QueryRow(`
		SELECT COALESCE(SUM(file_size), 0), COUNT(*)
		FROM files
		WHERE expires_at > datetime('now')
	`).Scan(&storageUsed, &fileCount)

	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if storageUsed != 0 {
		t.Errorf("Expected 0 storage used, got %d", storageUsed)
	}

	if fileCount != 0 {
		t.Errorf("Expected 0 files, got %d", fileCount)
	}
}

func TestDatabaseMetricsCollector_WithData(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test files
	_, err := db.Exec(`
		INSERT INTO files (claim_code, original_filename, stored_filename, file_size, mime_type, expires_at, uploader_ip, sha256_hash)
		VALUES
			('code1', 'file1.txt', 'uuid1.txt', 1024, 'text/plain', datetime('now', '+1 day'), '127.0.0.1', 'hash1'),
			('code2', 'file2.txt', 'uuid2.txt', 2048, 'text/plain', datetime('now', '+1 day'), '127.0.0.1', 'hash2'),
			('code3', 'file3.txt', 'uuid3.txt', 4096, 'text/plain', datetime('now', '-1 day'), '127.0.0.1', 'hash3')
	`)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	// Insert partial uploads
	_, err = db.Exec(`
		INSERT INTO partial_uploads (upload_id, filename, total_size, chunk_size, total_chunks, expires_in_hours, max_downloads, completed)
		VALUES
			('upload1', 'file.bin', 10485760, 1048576, 10, 24, 5, 0),
			('upload2', 'file2.bin', 20971520, 1048576, 20, 24, 5, 0),
			('upload3', 'file3.bin', 5242880, 1048576, 5, 24, 5, 1)
	`)
	if err != nil {
		t.Fatalf("Failed to insert partial upload data: %v", err)
	}

	collector := NewDatabaseMetricsCollector(db, 10.0) // 10 GB quota

	// Test storage query
	var storageUsed int64
	var fileCount int64
	err = db.QueryRow(`
		SELECT COALESCE(SUM(file_size), 0), COUNT(*)
		FROM files
		WHERE expires_at > datetime('now')
	`).Scan(&storageUsed, &fileCount)

	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	expectedStorage := int64(1024 + 2048) // file1 + file2 (file3 is expired)
	if storageUsed != expectedStorage {
		t.Errorf("Expected %d bytes storage used, got %d", expectedStorage, storageUsed)
	}

	if fileCount != 2 {
		t.Errorf("Expected 2 active files, got %d", fileCount)
	}

	// Test partial uploads query
	var partialCount int64
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM partial_uploads
		WHERE completed = 0
	`).Scan(&partialCount)

	if err != nil {
		t.Fatalf("Partial uploads query failed: %v", err)
	}

	if partialCount != 2 {
		t.Errorf("Expected 2 active partial uploads, got %d", partialCount)
	}

	// Test quota calculation
	quotaBytes := collector.quotaLimitGB * 1024 * 1024 * 1024
	expectedQuotaBytes := 10.0 * 1024 * 1024 * 1024
	if quotaBytes != expectedQuotaBytes {
		t.Errorf("Expected quota %f bytes, got %f", expectedQuotaBytes, quotaBytes)
	}

	quotaUsedPercent := (float64(storageUsed) / quotaBytes) * 100
	if quotaUsedPercent <= 0 || quotaUsedPercent >= 100 {
		t.Logf("Quota used: %.6f%% (storage: %d bytes, quota: %.0f bytes)", quotaUsedPercent, storageUsed, quotaBytes)
		// This is expected for small test files
	}
}

func TestDatabaseMetricsCollector_UnlimitedQuota(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	collector := NewDatabaseMetricsCollector(db, 0) // Unlimited quota

	quotaBytes := collector.quotaLimitGB * 1024 * 1024 * 1024
	if quotaBytes != 0 {
		t.Errorf("Expected 0 quota bytes for unlimited, got %f", quotaBytes)
	}

	// With unlimited quota, percentage should be 0
	storageUsed := int64(1024)
	var quotaUsedPercent float64
	if quotaBytes > 0 {
		quotaUsedPercent = (float64(storageUsed) / quotaBytes) * 100
	}

	if quotaUsedPercent != 0 {
		t.Errorf("Expected 0%% quota used for unlimited, got %.2f%%", quotaUsedPercent)
	}
}
