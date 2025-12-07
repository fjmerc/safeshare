package repository

import (
	"context"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// UserRepository defines the interface for user-related database operations.
// All methods accept a context for cancellation and timeout support.
type UserRepository interface {
	// Create inserts a new user record into the database.
	// Returns the created user with populated ID and timestamps.
	Create(ctx context.Context, username, email, passwordHash, role string, requirePasswordChange bool) (*models.User, error)

	// GetByID retrieves a user by database ID.
	// Returns nil, nil if the user doesn't exist.
	GetByID(ctx context.Context, id int64) (*models.User, error)

	// GetByUsername retrieves a user by username.
	// Returns nil, nil if the user doesn't exist.
	GetByUsername(ctx context.Context, username string) (*models.User, error)

	// UpdateLastLogin updates the last login timestamp for a user.
	UpdateLastLogin(ctx context.Context, userID int64) error

	// UpdatePassword updates a user's password hash.
	// If clearPasswordChangeFlag is true, the require_password_change flag is cleared.
	UpdatePassword(ctx context.Context, userID int64, passwordHash string, clearPasswordChangeFlag bool) error

	// Update updates user details (username, email, role).
	Update(ctx context.Context, userID int64, username, email, role string) error

	// SetActive enables or disables a user account.
	SetActive(ctx context.Context, userID int64, isActive bool) error

	// Delete removes a user from the database and cleans up their physical files.
	// The uploadDir parameter specifies where physical files are stored.
	Delete(ctx context.Context, userID int64, uploadDir string) error

	// GetAll retrieves all users with pagination.
	// Returns (users, totalCount, error).
	GetAll(ctx context.Context, limit, offset int) ([]models.UserListItem, int, error)

	// Session operations

	// CreateSession creates a new user session.
	CreateSession(ctx context.Context, userID int64, token string, expiresAt time.Time, ipAddress, userAgent string) error

	// GetSession retrieves a session by token.
	// Returns nil, nil if the session doesn't exist or is expired.
	GetSession(ctx context.Context, token string) (*models.UserSession, error)

	// UpdateSessionActivity updates the last activity timestamp for a session.
	UpdateSessionActivity(ctx context.Context, token string) error

	// DeleteSession deletes a session (logout).
	DeleteSession(ctx context.Context, token string) error

	// DeleteSessionsByUserID deletes all sessions for a specific user.
	// Used when password is changed/reset to invalidate all existing sessions.
	DeleteSessionsByUserID(ctx context.Context, userID int64) error

	// CleanupExpiredSessions removes expired user sessions.
	CleanupExpiredSessions(ctx context.Context) error

	// User file operations

	// GetFiles retrieves all files uploaded by a specific user with pagination.
	// Returns (files, totalCount, error).
	GetFiles(ctx context.Context, userID int64, limit, offset int) ([]models.File, int, error)

	// DeleteFile deletes a file if it belongs to the specified user.
	// Returns the deleted file information and nil on success.
	DeleteFile(ctx context.Context, fileID, userID int64) (*models.File, error)

	// DeleteFileByClaimCode deletes a file by claim code if it belongs to the specified user.
	// Returns the deleted file information and nil on success.
	DeleteFileByClaimCode(ctx context.Context, claimCode string, userID int64) (*models.File, error)

	// UpdateFileName updates the original filename for a file owned by the specified user.
	UpdateFileName(ctx context.Context, fileID, userID int64, newFilename string) error

	// UpdateFileNameByClaimCode updates the original filename for a file identified by claim code.
	UpdateFileNameByClaimCode(ctx context.Context, claimCode string, userID int64, newFilename string) error

	// UpdateFileExpiration updates the expiration date for a file owned by the specified user.
	UpdateFileExpiration(ctx context.Context, fileID, userID int64, newExpiration time.Time) error

	// UpdateFileExpirationByClaimCode updates the expiration date for a file identified by claim code.
	UpdateFileExpirationByClaimCode(ctx context.Context, claimCode string, userID int64, newExpiration time.Time) error

	// GetFileByClaimCode retrieves a file by claim code if it belongs to the specified user.
	// Returns nil, nil if not found.
	GetFileByClaimCode(ctx context.Context, claimCode string, userID int64) (*models.File, error)
}
