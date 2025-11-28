package models

import "time"

// User represents a user account in the system
type User struct {
	ID                    int64
	Username              string
	Email                 string
	PasswordHash          string
	Role                  string // 'user' or 'admin'
	IsApproved            bool
	IsActive              bool // For soft disable functionality
	RequirePasswordChange bool // Flag for temporary passwords
	CreatedAt             time.Time
	LastLogin             *time.Time // nullable
}

// UserSession represents a user session
type UserSession struct {
	ID           int64
	UserID       int64
	SessionToken string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastActivity time.Time
	IPAddress    string
	UserAgent    string
}

// CreateUserRequest is the request body for creating a new user (admin only)
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"` // Optional: if empty, auto-generate
}

// CreateUserResponse is the response after creating a new user
type CreateUserResponse struct {
	ID                int64  `json:"id"`
	Username          string `json:"username"`
	Email             string `json:"email"`
	TemporaryPassword string `json:"temporary_password,omitempty"` // Only returned on creation
}

// UpdateUserRequest is the request body for updating a user
type UpdateUserRequest struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role,omitempty"`
}

// UserLoginRequest is the login request body
type UserLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserLoginResponse is the login response
type UserLoginResponse struct {
	ID                    int64  `json:"id"`
	Username              string `json:"username"`
	Email                 string `json:"email"`
	Role                  string `json:"role"`
	RequirePasswordChange bool   `json:"require_password_change"`
}

// ChangePasswordRequest is the request body for changing password
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// UserListItem represents a user in the admin user list
type UserListItem struct {
	ID        int64      `json:"id"`
	Username  string     `json:"username"`
	Email     string     `json:"email"`
	Role      string     `json:"role"`
	IsActive  bool       `json:"is_active"`
	CreatedAt time.Time  `json:"created_at"`
	LastLogin *time.Time `json:"last_login"`
	FileCount int        `json:"file_count"`
}
