package repository

import (
	"testing"
)

func TestDefaultPagination(t *testing.T) {
	opts := DefaultPagination()

	if opts.Limit != 20 {
		t.Errorf("DefaultPagination().Limit = %d, want 20", opts.Limit)
	}

	if opts.Offset != 0 {
		t.Errorf("DefaultPagination().Offset = %d, want 0", opts.Offset)
	}
}

func TestPaginationOptions(t *testing.T) {
	opts := PaginationOptions{
		Limit:  50,
		Offset: 10,
	}

	if opts.Limit != 50 {
		t.Errorf("Limit = %d, want 50", opts.Limit)
	}

	if opts.Offset != 10 {
		t.Errorf("Offset = %d, want 10", opts.Offset)
	}
}

func TestSortOptions(t *testing.T) {
	opts := SortOptions{
		Field:     "created_at",
		Ascending: true,
	}

	if opts.Field != "created_at" {
		t.Errorf("Field = %q, want %q", opts.Field, "created_at")
	}

	if !opts.Ascending {
		t.Error("Ascending should be true")
	}
}

func TestErrorVariables(t *testing.T) {
	// Test that error messages are as expected
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{"ErrNotFound", ErrNotFound, "entity not found"},
		{"ErrDuplicateKey", ErrDuplicateKey, "duplicate key"},
		{"ErrQuotaExceeded", ErrQuotaExceeded, "quota exceeded"},
		{"ErrLimitReached", ErrLimitReached, "limit reached"},
		{"ErrClaimCodeChanged", ErrClaimCodeChanged, "claim code changed during operation"},
		{"ErrConcurrentModification", ErrConcurrentModification, "concurrent modification detected"},
		{"ErrInvalidInput", ErrInvalidInput, "invalid input"},
		{"ErrNilDatabase", ErrNilDatabase, "nil database connection"},
		{"ErrServiceUnavailable", ErrServiceUnavailable, "service temporarily unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.wantMsg {
				t.Errorf("%s.Error() = %q, want %q", tt.name, tt.err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestFileStats(t *testing.T) {
	stats := FileStats{
		TotalFiles:   100,
		StorageUsed:  1024 * 1024 * 1024, // 1GB
		ActiveFiles:  90,
		ExpiredFiles: 10,
		TotalUsage:   2 * 1024 * 1024 * 1024, // 2GB
	}

	if stats.TotalFiles != 100 {
		t.Errorf("TotalFiles = %d, want 100", stats.TotalFiles)
	}

	if stats.ActiveFiles+stats.ExpiredFiles != stats.TotalFiles {
		t.Error("ActiveFiles + ExpiredFiles should equal TotalFiles")
	}
}

func TestAdminSession(t *testing.T) {
	session := AdminSession{
		ID:           1,
		SessionToken: "test-token",
		IPAddress:    "192.168.1.1",
		UserAgent:    "Mozilla/5.0",
	}

	if session.ID != 1 {
		t.Errorf("ID = %d, want 1", session.ID)
	}

	if session.SessionToken != "test-token" {
		t.Errorf("SessionToken = %q, want test-token", session.SessionToken)
	}
}

func TestBlockedIP(t *testing.T) {
	blocked := BlockedIP{
		ID:        1,
		IPAddress: "10.0.0.1",
		Reason:    "suspicious activity",
		BlockedBy: "admin",
	}

	if blocked.IPAddress != "10.0.0.1" {
		t.Errorf("IPAddress = %q, want 10.0.0.1", blocked.IPAddress)
	}

	if blocked.Reason != "suspicious activity" {
		t.Errorf("Reason = %q, want suspicious activity", blocked.Reason)
	}
}

func TestExpiredFileInfo(t *testing.T) {
	info := ExpiredFileInfo{
		ClaimCode:        "ABC123",
		OriginalFilename: "test.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
	}

	if info.ClaimCode != "ABC123" {
		t.Errorf("ClaimCode = %q, want ABC123", info.ClaimCode)
	}

	if info.OriginalFilename != "test.txt" {
		t.Errorf("OriginalFilename = %q, want test.txt", info.OriginalFilename)
	}
}

func TestDatabaseTypeConstants(t *testing.T) {
	if DatabaseTypeSQLite != "sqlite" {
		t.Errorf("DatabaseTypeSQLite = %q, want sqlite", DatabaseTypeSQLite)
	}

	if DatabaseTypePostgreSQL != "postgresql" {
		t.Errorf("DatabaseTypePostgreSQL = %q, want postgresql", DatabaseTypePostgreSQL)
	}
}
