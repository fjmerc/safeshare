// Package repository defines interfaces for data access operations.
// This package provides abstractions for database operations, allowing
// different backend implementations (SQLite, PostgreSQL) to be swapped
// without changing application code.
//
// The repository pattern encapsulates database-specific SQL and provides
// a clean interface for handlers and services to interact with data.
package repository

import (
	"errors"
	"time"
)

// Common errors returned by repository operations.
var (
	// ErrNotFound is returned when a requested entity does not exist.
	ErrNotFound = errors.New("entity not found")

	// ErrDuplicateKey is returned when an insert violates a uniqueness constraint.
	ErrDuplicateKey = errors.New("duplicate key")

	// ErrQuotaExceeded is returned when an operation would exceed storage quota.
	ErrQuotaExceeded = errors.New("quota exceeded")

	// ErrLimitReached is returned when a limit (e.g., max downloads) has been reached.
	ErrLimitReached = errors.New("limit reached")

	// ErrClaimCodeChanged is returned when a claim code was modified during an operation.
	ErrClaimCodeChanged = errors.New("claim code changed during operation")

	// ErrConcurrentModification is returned when a concurrent modification is detected.
	ErrConcurrentModification = errors.New("concurrent modification detected")

	// ErrInvalidInput is returned when input validation fails.
	ErrInvalidInput = errors.New("invalid input")

	// ErrNilDatabase is returned when a nil database connection is provided.
	ErrNilDatabase = errors.New("nil database connection")

	// ErrServiceUnavailable is returned when a service is temporarily unavailable.
	ErrServiceUnavailable = errors.New("service temporarily unavailable")
)

// FileStats contains statistics about file storage.
type FileStats struct {
	TotalFiles   int
	StorageUsed  int64
	ActiveFiles  int   // Files that haven't expired
	ExpiredFiles int   // Files past expiration but not yet cleaned up
	TotalUsage   int64 // Includes partial uploads
}

// AdminSession represents an admin session.
type AdminSession struct {
	ID           int64
	SessionToken string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
	IPAddress    string
	UserAgent    string
}

// BlockedIP represents a blocked IP address.
type BlockedIP struct {
	ID        int64
	IPAddress string
	Reason    string
	BlockedAt time.Time
	BlockedBy string
}

// ExpiredFileInfo contains information about an expired file for webhook callbacks.
type ExpiredFileInfo struct {
	ClaimCode        string
	OriginalFilename string
	FileSize         int64
	MimeType         string
	ExpiresAt        time.Time
}

// PaginationOptions provides common pagination parameters.
type PaginationOptions struct {
	Limit  int
	Offset int
}

// SortOptions provides common sorting parameters.
type SortOptions struct {
	Field     string
	Ascending bool
}

// DefaultPagination returns default pagination options (limit 20, offset 0).
func DefaultPagination() PaginationOptions {
	return PaginationOptions{
		Limit:  20,
		Offset: 0,
	}
}
