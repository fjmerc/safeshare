package models

import "time"

// APIToken represents an API token in the database
type APIToken struct {
	ID          int64
	UserID      int64
	Name        string
	TokenHash   string     // SHA-256 hash of full token
	TokenPrefix string     // First 12 chars for identification (e.g., "safeshare_a1b2")
	Scopes      string     // Comma-separated scopes
	ExpiresAt   *time.Time // NULL = never expires
	LastUsedAt  *time.Time
	LastUsedIP  *string
	CreatedAt   time.Time
	CreatedIP   string
	IsActive    bool
}

// APITokenListItem represents a token in list responses (no hash exposed)
type APITokenListItem struct {
	ID          int64      `json:"id"`
	UserID      int64      `json:"user_id,omitempty"`  // Only included in admin responses
	Username    string     `json:"username,omitempty"` // Only included in admin responses
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"` // e.g., "safeshare_a1b2"
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
	IsActive    bool       `json:"is_active"`
}

// CreateAPITokenRequest is the request body for creating a new token
type CreateAPITokenRequest struct {
	Name          string   `json:"name"`                      // User-friendly name (required)
	Scopes        []string `json:"scopes"`                    // Requested scopes (required)
	ExpiresInDays *int     `json:"expires_in_days,omitempty"` // Days until expiration (null = never)
}

// CreateAPITokenResponse is the response after creating a token
type CreateAPITokenResponse struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Token       string     `json:"token"` // ONLY returned once at creation!
	TokenPrefix string     `json:"token_prefix"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	Warning     string     `json:"warning"` // "Save this token - it won't be shown again"
}

// APITokenScopes defines the valid scope values
var APITokenScopes = []string{"upload", "download", "manage", "admin"}

// APITokenScopeDescriptions provides descriptions for each scope
var APITokenScopeDescriptions = map[string]string{
	"upload":   "Upload files (simple and chunked)",
	"download": "Download files",
	"manage":   "Manage own files (delete, rename, update expiration)",
	"admin":    "Full admin access (requires admin role)",
}
