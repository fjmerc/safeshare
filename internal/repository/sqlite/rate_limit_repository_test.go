package sqlite

import (
	"context"
	"testing"
	"time"
)

func TestRateLimitRepository_IncrementAndCheck(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Create rate_limits table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rate_limits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			limit_type TEXT NOT NULL,
			request_count INTEGER NOT NULL DEFAULT 1,
			window_end TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(ip_address, limit_type)
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create rate_limits table: %v", err)
	}

	repo := NewRateLimitRepository(db)
	ctx := context.Background()

	t.Run("FirstRequestAllowed", func(t *testing.T) {
		allowed, count, err := repo.IncrementAndCheck(ctx, "192.168.1.1", "upload", 10, time.Hour)
		if err != nil {
			t.Fatalf("IncrementAndCheck failed: %v", err)
		}
		if !allowed {
			t.Error("First request should be allowed")
		}
		if count != 1 {
			t.Errorf("Expected count 1, got %d", count)
		}
	})

	t.Run("MultipleRequestsIncrementCount", func(t *testing.T) {
		ip := "192.168.1.2"
		for i := 1; i <= 5; i++ {
			allowed, count, err := repo.IncrementAndCheck(ctx, ip, "download", 10, time.Hour)
			if err != nil {
				t.Fatalf("IncrementAndCheck failed on request %d: %v", i, err)
			}
			if !allowed {
				t.Errorf("Request %d should be allowed", i)
			}
			if count != i {
				t.Errorf("Expected count %d, got %d", i, count)
			}
		}
	})

	t.Run("LimitExceeded", func(t *testing.T) {
		ip := "192.168.1.3"
		limit := 3

		// Make requests up to the limit
		for i := 1; i <= limit; i++ {
			allowed, _, err := repo.IncrementAndCheck(ctx, ip, "upload", limit, time.Hour)
			if err != nil {
				t.Fatalf("IncrementAndCheck failed: %v", err)
			}
			if !allowed {
				t.Errorf("Request %d should be allowed (limit=%d)", i, limit)
			}
		}

		// Next request should be denied
		allowed, count, err := repo.IncrementAndCheck(ctx, ip, "upload", limit, time.Hour)
		if err != nil {
			t.Fatalf("IncrementAndCheck failed: %v", err)
		}
		if allowed {
			t.Error("Request exceeding limit should be denied")
		}
		if count != limit+1 {
			t.Errorf("Expected count %d, got %d", limit+1, count)
		}
	})

	t.Run("DifferentLimitTypesSeparate", func(t *testing.T) {
		ip := "192.168.1.4"

		// Exhaust upload limit
		for i := 0; i < 2; i++ {
			repo.IncrementAndCheck(ctx, ip, "upload", 2, time.Hour)
		}

		// Should still be allowed for download
		allowed, count, err := repo.IncrementAndCheck(ctx, ip, "download", 2, time.Hour)
		if err != nil {
			t.Fatalf("IncrementAndCheck failed: %v", err)
		}
		if !allowed {
			t.Error("Different limit type should be allowed")
		}
		if count != 1 {
			t.Errorf("Expected count 1 for new limit type, got %d", count)
		}
	})

	t.Run("DifferentIPsSeparate", func(t *testing.T) {
		// Exhaust limit for one IP
		for i := 0; i < 2; i++ {
			repo.IncrementAndCheck(ctx, "10.0.0.1", "chunk", 2, time.Hour)
		}

		// Different IP should still be allowed
		allowed, count, err := repo.IncrementAndCheck(ctx, "10.0.0.2", "chunk", 2, time.Hour)
		if err != nil {
			t.Fatalf("IncrementAndCheck failed: %v", err)
		}
		if !allowed {
			t.Error("Different IP should be allowed")
		}
		if count != 1 {
			t.Errorf("Expected count 1 for new IP, got %d", count)
		}
	})

	t.Run("InvalidInputs", func(t *testing.T) {
		// Empty IP
		_, _, err := repo.IncrementAndCheck(ctx, "", "upload", 10, time.Hour)
		if err == nil {
			t.Error("Expected error for empty IP address")
		}

		// Invalid IP format
		_, _, err = repo.IncrementAndCheck(ctx, "not-an-ip", "upload", 10, time.Hour)
		if err == nil {
			t.Error("Expected error for invalid IP address format")
		}

		// IP address too long
		_, _, err = repo.IncrementAndCheck(ctx, "123456789012345678901234567890123456789012345678901234567890", "upload", 10, time.Hour)
		if err == nil {
			t.Error("Expected error for IP address too long")
		}

		// Empty limit type
		_, _, err = repo.IncrementAndCheck(ctx, "1.2.3.4", "", 10, time.Hour)
		if err == nil {
			t.Error("Expected error for empty limit type")
		}

		// Invalid limit type
		_, _, err = repo.IncrementAndCheck(ctx, "1.2.3.4", "invalid_type", 10, time.Hour)
		if err == nil {
			t.Error("Expected error for invalid limit type")
		}

		// Zero limit
		_, _, err = repo.IncrementAndCheck(ctx, "1.2.3.4", "upload", 0, time.Hour)
		if err == nil {
			t.Error("Expected error for zero limit")
		}

		// Limit too high
		_, _, err = repo.IncrementAndCheck(ctx, "1.2.3.4", "upload", 100000, time.Hour)
		if err == nil {
			t.Error("Expected error for limit exceeding maximum")
		}

		// Zero window duration
		_, _, err = repo.IncrementAndCheck(ctx, "1.2.3.4", "upload", 10, 0)
		if err == nil {
			t.Error("Expected error for zero window duration")
		}
	})
}

func TestRateLimitRepository_GetEntry(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rate_limits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			limit_type TEXT NOT NULL,
			request_count INTEGER NOT NULL DEFAULT 1,
			window_end TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(ip_address, limit_type)
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create rate_limits table: %v", err)
	}

	repo := NewRateLimitRepository(db)
	ctx := context.Background()

	t.Run("GetNonExistent", func(t *testing.T) {
		entry, err := repo.GetEntry(ctx, "192.168.1.100", "admin_login")
		if err != nil {
			t.Fatalf("GetEntry failed: %v", err)
		}
		if entry != nil {
			t.Error("Expected nil for non-existent entry")
		}
	})

	t.Run("GetExisting", func(t *testing.T) {
		ip := "192.168.1.5"
		limitType := "user_login"

		// Create an entry
		repo.IncrementAndCheck(ctx, ip, limitType, 10, time.Hour)
		repo.IncrementAndCheck(ctx, ip, limitType, 10, time.Hour)

		entry, err := repo.GetEntry(ctx, ip, limitType)
		if err != nil {
			t.Fatalf("GetEntry failed: %v", err)
		}
		if entry == nil {
			t.Fatal("Expected entry, got nil")
		}
		if entry.IPAddress != ip {
			t.Errorf("Expected IP %s, got %s", ip, entry.IPAddress)
		}
		if entry.LimitType != limitType {
			t.Errorf("Expected limit type %s, got %s", limitType, entry.LimitType)
		}
		if entry.Count != 2 {
			t.Errorf("Expected count 2, got %d", entry.Count)
		}
	})
}

func TestRateLimitRepository_ResetEntry(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rate_limits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			limit_type TEXT NOT NULL,
			request_count INTEGER NOT NULL DEFAULT 1,
			window_end TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(ip_address, limit_type)
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create rate_limits table: %v", err)
	}

	repo := NewRateLimitRepository(db)
	ctx := context.Background()

	ip := "192.168.1.6"
	limitType := "regeneration"

	// Create entry by making requests
	repo.IncrementAndCheck(ctx, ip, limitType, 10, time.Hour)
	repo.IncrementAndCheck(ctx, ip, limitType, 10, time.Hour)

	// Verify entry exists
	entry, _ := repo.GetEntry(ctx, ip, limitType)
	if entry == nil {
		t.Fatal("Entry should exist before reset")
	}

	// Reset entry
	err = repo.ResetEntry(ctx, ip, limitType)
	if err != nil {
		t.Fatalf("ResetEntry failed: %v", err)
	}

	// Verify entry is gone
	entry, _ = repo.GetEntry(ctx, ip, limitType)
	if entry != nil {
		t.Error("Entry should be nil after reset")
	}

	// Next request should start fresh
	allowed, count, _ := repo.IncrementAndCheck(ctx, ip, limitType, 10, time.Hour)
	if !allowed {
		t.Error("Request after reset should be allowed")
	}
	if count != 1 {
		t.Errorf("Expected count 1 after reset, got %d", count)
	}
}

func TestRateLimitRepository_CleanupExpired(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rate_limits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			limit_type TEXT NOT NULL,
			request_count INTEGER NOT NULL DEFAULT 1,
			window_end TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(ip_address, limit_type)
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create rate_limits table: %v", err)
	}

	repo := NewRateLimitRepository(db)
	ctx := context.Background()

	// Create an entry that's already expired (2 hours ago)
	expiredTime := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	_, err = db.Exec(`
		INSERT INTO rate_limits (ip_address, limit_type, request_count, window_end, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "1.2.3.4", "upload", 5, expiredTime, expiredTime, expiredTime)
	if err != nil {
		t.Fatalf("Failed to insert expired entry: %v", err)
	}

	// Create a fresh entry
	repo.IncrementAndCheck(ctx, "5.6.7.8", "upload", 10, time.Hour)

	// Run cleanup
	count, err := repo.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired failed: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 entry cleaned up, got %d", count)
	}

	// Verify expired entry is gone
	entry, _ := repo.GetEntry(ctx, "1.2.3.4", "upload")
	if entry != nil {
		t.Error("Expired entry should have been removed")
	}

	// Verify fresh entry still exists
	entry, _ = repo.GetEntry(ctx, "5.6.7.8", "upload")
	if entry == nil {
		t.Error("Fresh entry should still exist")
	}
}

func TestRateLimitRepository_GetAllEntriesForIP(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rate_limits (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL,
			limit_type TEXT NOT NULL,
			request_count INTEGER NOT NULL DEFAULT 1,
			window_end TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(ip_address, limit_type)
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create rate_limits table: %v", err)
	}

	repo := NewRateLimitRepository(db)
	ctx := context.Background()

	ip := "192.168.1.7"

	// Create entries for different limit types
	repo.IncrementAndCheck(ctx, ip, "upload", 10, time.Hour)
	repo.IncrementAndCheck(ctx, ip, "download", 10, time.Hour)
	repo.IncrementAndCheck(ctx, ip, "download", 10, time.Hour) // Increment download
	repo.IncrementAndCheck(ctx, "10.20.30.40", "upload", 10, time.Hour) // Different IP

	entries, err := repo.GetAllEntriesForIP(ctx, ip)
	if err != nil {
		t.Fatalf("GetAllEntriesForIP failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(entries))
	}

	// Check entries are sorted by limit_type
	if entries[0].LimitType != "download" {
		t.Errorf("Expected first entry to be download, got %s", entries[0].LimitType)
	}
	if entries[0].Count != 2 {
		t.Errorf("Expected download count 2, got %d", entries[0].Count)
	}
	if entries[1].LimitType != "upload" {
		t.Errorf("Expected second entry to be upload, got %s", entries[1].LimitType)
	}
}
