package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

// Context keys for auth information
type contextKey string

const (
	// ContextKeyUser stores the authenticated user in request context
	ContextKeyUser contextKey = "user"

	// ContextKeyAuthType stores the authentication method used (session or api_token)
	ContextKeyAuthType contextKey = "auth_type"

	// ContextKeyTokenID stores the API token ID if token auth was used
	ContextKeyTokenID contextKey = "api_token_id"

	// ContextKeyTokenScopes stores the API token scopes if token auth was used
	ContextKeyTokenScopes contextKey = "api_token_scopes"
)

// Authentication type constants
const (
	AuthTypeSession  = "session"
	AuthTypeAPIToken = "api_token"
)

// extractBearerToken extracts the token from Authorization: Bearer header
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	// Check for "Bearer " prefix (case-insensitive)
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

// UserAuth middleware checks for valid user session OR API token
// It tries Bearer token first, then falls back to session cookie
func UserAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try Bearer token first
			bearerToken := extractBearerToken(r)
			if bearerToken != "" {
				user, ctx, err := authenticateWithAPIToken(db, r, bearerToken)
				if err != nil {
					handleAuthError(w, r, err)
					return
				}
				if user != nil {
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// Token was provided but invalid - error was already handled by authenticateWithAPIToken
				return
			}

			// Fall back to session-based auth
			user, ctx, err := authenticateWithSession(db, r)
			if err != nil {
				handleAuthError(w, r, err)
				return
			}
			if user == nil {
				slog.Warn("user authentication failed - no valid credentials",
					"path", r.URL.Path,
					"ip", getClientIP(r),
				)
				// Redirect HTML requests to login page
				if isHTMLRequest(r) {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalUserAuth middleware checks for a user session or API token but doesn't require it
// If valid auth exists, it adds the user to the context
// If no auth or invalid auth, it continues without error
func OptionalUserAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try Bearer token first
			bearerToken := extractBearerToken(r)
			if bearerToken != "" {
				user, ctx, err := authenticateWithAPIToken(db, r, bearerToken)
				if err == nil && user != nil {
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// Invalid token in optional auth - continue without user
				// (Don't return error, just proceed anonymously)
			}

			// Try session-based auth
			user, ctx, _ := authenticateWithSession(db, r)
			if user != nil {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// No valid auth, continue without user
			next.ServeHTTP(w, r)
		})
	}
}

// tokenAuthBaseDelay is the minimum time for token authentication to prevent timing attacks
// This ensures invalid/expired token responses take roughly the same time as valid ones
const tokenAuthBaseDelay = 5 * time.Millisecond

// authenticateWithAPIToken validates a Bearer token and returns the user
func authenticateWithAPIToken(db *sql.DB, r *http.Request, token string) (*models.User, context.Context, error) {
	authStart := time.Now()

	// Helper to ensure consistent response times (prevents timing attacks)
	normalizeResponseTime := func() {
		elapsed := time.Since(authStart)
		if elapsed < tokenAuthBaseDelay {
			time.Sleep(tokenAuthBaseDelay - elapsed)
		}
	}

	// Validate token format first (fast check before DB query)
	if !utils.ValidateAPITokenFormat(token) {
		normalizeResponseTime()
		slog.Warn("invalid API token format",
			"path", r.URL.Path,
			"ip", getClientIP(r),
		)
		return nil, nil, &authError{
			message:    "Invalid API token",
			statusCode: http.StatusUnauthorized,
		}
	}

	// Hash the token and look it up
	tokenHash := utils.HashAPIToken(token)
	apiToken, err := database.GetAPITokenByHash(db, tokenHash)
	if err != nil {
		normalizeResponseTime()
		slog.Error("failed to validate API token",
			"error", err,
			"ip", getClientIP(r),
		)
		return nil, nil, &authError{
			message:    "Internal server error",
			statusCode: http.StatusInternalServerError,
		}
	}

	// Token not found or revoked - use generic error message to prevent enumeration
	if apiToken == nil {
		normalizeResponseTime()
		slog.Warn("API token not found or revoked",
			"path", r.URL.Path,
			"ip", getClientIP(r),
		)
		return nil, nil, &authError{
			message:    "Invalid API token",
			statusCode: http.StatusUnauthorized,
		}
	}

	// Check expiration - use same generic error message
	if apiToken.ExpiresAt != nil && time.Now().After(*apiToken.ExpiresAt) {
		normalizeResponseTime()
		slog.Warn("API token expired",
			"token_id", apiToken.ID,
			"token_prefix", apiToken.TokenPrefix,
			"path", r.URL.Path,
		)
		return nil, nil, &authError{
			message:    "Invalid API token",
			statusCode: http.StatusUnauthorized,
		}
	}

	// Get associated user
	user, err := database.GetUserByID(db, apiToken.UserID)
	if err != nil {
		slog.Error("failed to get user for API token",
			"error", err,
			"token_id", apiToken.ID,
		)
		return nil, nil, &authError{
			message:    "Internal server error",
			statusCode: http.StatusInternalServerError,
		}
	}

	if user == nil {
		slog.Warn("API token user not found",
			"token_id", apiToken.ID,
			"user_id", apiToken.UserID,
		)
		return nil, nil, &authError{
			message:    "Invalid API token",
			statusCode: http.StatusUnauthorized,
		}
	}

	if !user.IsActive {
		slog.Warn("API token user account disabled",
			"user_id", user.ID,
			"username", user.Username,
			"token_id", apiToken.ID,
		)
		return nil, nil, &authError{
			message:    "Account has been disabled",
			statusCode: http.StatusForbidden,
		}
	}

	// Update last used (async, don't block request)
	clientIP := getClientIP(r)
	go func() {
		if err := database.UpdateAPITokenLastUsed(db, apiToken.ID, clientIP); err != nil {
			slog.Error("failed to update token last used", "error", err)
		}
	}()

	slog.Debug("API token authentication successful",
		"user_id", user.ID,
		"username", user.Username,
		"token_id", apiToken.ID,
		"token_prefix", apiToken.TokenPrefix,
	)

	// Set context values
	ctx := context.WithValue(r.Context(), ContextKeyUser, user)
	ctx = context.WithValue(ctx, ContextKeyAuthType, AuthTypeAPIToken)
	ctx = context.WithValue(ctx, ContextKeyTokenID, apiToken.ID)
	ctx = context.WithValue(ctx, ContextKeyTokenScopes, apiToken.Scopes)

	return user, ctx, nil
}

// authenticateWithSession validates a session cookie and returns the user
func authenticateWithSession(db *sql.DB, r *http.Request) (*models.User, context.Context, error) {
	// Get session token from cookie
	cookie, err := r.Cookie("user_session")
	if err != nil {
		// No cookie is not an error, just no session
		return nil, nil, nil
	}

	// Validate session
	session, err := database.GetUserSession(db, cookie.Value)
	if err != nil {
		slog.Error("failed to validate user session",
			"error", err,
			"ip", getClientIP(r),
		)
		return nil, nil, &authError{
			message:    "Internal server error",
			statusCode: http.StatusInternalServerError,
		}
	}

	if session == nil {
		return nil, nil, nil
	}

	// Get user info
	user, err := database.GetUserByID(db, session.UserID)
	if err != nil {
		slog.Error("failed to get user",
			"error", err,
			"user_id", session.UserID,
		)
		return nil, nil, &authError{
			message:    "Internal server error",
			statusCode: http.StatusInternalServerError,
		}
	}

	if user == nil {
		return nil, nil, nil
	}

	// Check if user is active
	if !user.IsActive {
		slog.Warn("user authentication failed - account disabled",
			"user_id", user.ID,
			"username", user.Username,
		)
		return nil, nil, &authError{
			message:    "Account has been disabled",
			statusCode: http.StatusForbidden,
		}
	}

	// Update session activity
	if err := database.UpdateUserSessionActivity(db, cookie.Value); err != nil {
		slog.Error("failed to update user session activity", "error", err)
		// Don't fail the request, just log the error
	}

	// Set context values
	ctx := context.WithValue(r.Context(), ContextKeyUser, user)
	ctx = context.WithValue(ctx, ContextKeyAuthType, AuthTypeSession)

	return user, ctx, nil
}

// RequireScope middleware ensures the API token has the required scope
// Must be used AFTER UserAuth middleware
// Session auth bypasses scope checks (has full access)
func RequireScope(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authType, ok := r.Context().Value(ContextKeyAuthType).(string)
			if !ok {
				// No auth type set means no auth happened
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Session auth has all scopes (full access)
			if authType == AuthTypeSession {
				next.ServeHTTP(w, r)
				return
			}

			// Check API token scopes
			scopes, ok := r.Context().Value(ContextKeyTokenScopes).(string)
			if !ok {
				slog.Error("API token scopes not found in context")
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !utils.HasScope(scopes, requiredScope) {
				slog.Warn("API token missing required scope",
					"required", requiredScope,
					"has", scopes,
					"path", r.URL.Path,
				)
				http.Error(w, fmt.Sprintf("Token missing required scope: %s", requiredScope), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext retrieves the authenticated user from request context
// Returns nil if no user is authenticated
func GetUserFromContext(r *http.Request) *models.User {
	user, ok := r.Context().Value(ContextKeyUser).(*models.User)
	if !ok {
		return nil
	}
	return user
}

// GetAuthTypeFromContext retrieves the authentication type from request context
// Returns empty string if not set
func GetAuthTypeFromContext(r *http.Request) string {
	authType, ok := r.Context().Value(ContextKeyAuthType).(string)
	if !ok {
		return ""
	}
	return authType
}

// GetTokenScopesFromContext retrieves the API token scopes from request context
// Returns empty string if not using token auth
func GetTokenScopesFromContext(r *http.Request) string {
	scopes, ok := r.Context().Value(ContextKeyTokenScopes).(string)
	if !ok {
		return ""
	}
	return scopes
}

// authError represents an authentication error with HTTP status code
type authError struct {
	message    string
	statusCode int
}

func (e *authError) Error() string {
	return e.message
}

// handleAuthError sends an appropriate error response based on the error type
func handleAuthError(w http.ResponseWriter, r *http.Request, err error) {
	if authErr, ok := err.(*authError); ok {
		if authErr.statusCode == http.StatusForbidden {
			// Forbidden is different from unauthorized
			http.Error(w, authErr.message, authErr.statusCode)
			return
		}
		// For HTML requests, redirect to login
		if isHTMLRequest(r) && authErr.statusCode == http.StatusUnauthorized {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		http.Error(w, authErr.message, authErr.statusCode)
		return
	}
	// Generic error
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

// isHTMLRequest detects if the request is for an HTML page vs an API endpoint
func isHTMLRequest(r *http.Request) bool {
	// API requests start with /api/
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	// Check Accept header for HTML
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}
