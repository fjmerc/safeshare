package backup

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestBackupStats_IncludesBundles(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	createTestDatabase(t, dbPath)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE bundles (id INTEGER PRIMARY KEY); INSERT INTO bundles DEFAULT VALUES; INSERT INTO bundles DEFAULT VALUES;`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	stats, err := GetDatabaseStats(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if stats.BundlesCount != 2 {
		t.Fatalf("BundlesCount = %d, want 2", stats.BundlesCount)
	}

	found := false
	for _, table := range FullDatabaseTables {
		found = found || table == "bundles"
	}
	if !found {
		t.Fatal("bundles is not in FullDatabaseTables")
	}

	// A database from before bundles existed still reports stats.
	oldPath := filepath.Join(t.TempDir(), "old.db")
	createTestDatabase(t, oldPath)
	if stats, err := GetDatabaseStats(oldPath); err != nil || stats.BundlesCount != 0 {
		t.Fatalf("old database: %+v %v", stats, err)
	}
}
