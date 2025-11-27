package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

// Maximum number of tokens per user to prevent abuse
const maxTokensPerUser = 50

// Maximum expiration in days for API tokens (1 year)
const maxTokenExpirationDays = 365

// CreateAPITokenHandler creates a new API token for the authenticated user
// Tokens can only be created via session auth (not via existing API token)
func CreateAPITokenHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Only allow token creation via session auth (security: tokens can't create tokens)
		authType := middleware.GetAuthTypeFromContext(r)
		if authType != middleware.AuthTypeSession {
			slog.Warn("API token creation attempted via API token",
				"user_id", user.ID,
				"username", user.Username,
			)
			http.Error(w, "Token creation requires session authentication (login via web)", http.StatusForbidden)
			return
		}

		// Parse request
		var req models.CreateAPITokenRequest
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse create token request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
				"code":  "INVALID_JSON",
			})
			return
		}

		// Validate name
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Token name is required",
				"code":  "MISSING_NAME",
			})
			return
		}
		if len(req.Name) > 100 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Token name must be 100 characters or less",
				"code":  "NAME_TOO_LONG",
			})
			return
		}

		// Validate scopes
		if len(req.Scopes) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "At least one scope is required",
				"code":  "MISSING_SCOPES",
			})
			return
		}

		// Normalize and validate scopes
		req.Scopes = utils.NormalizeScopes(req.Scopes)
		invalidScopes, err := utils.ValidateScopes(req.Scopes)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":          "Invalid scopes provided",
				"code":           "INVALID_SCOPES",
				"invalid_scopes": invalidScopes,
				"valid_scopes":   utils.ValidAPITokenScopes,
			})
			return
		}

		// Check admin scope restriction
		for _, scope := range req.Scopes {
			if scope == "admin" && user.Role != "admin" {
				slog.Warn("non-admin user attempted to create token with admin scope",
					"user_id", user.ID,
					"username", user.Username,
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Only admin users can create tokens with admin scope",
					"code":  "FORBIDDEN_SCOPE",
				})
				return
			}
		}

		// Check if user has too many tokens
		tokenCount, err := database.CountAPITokensByUserID(db, user.ID)
		if err != nil {
			slog.Error("failed to count user tokens", "error", err, "user_id", user.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if tokenCount >= maxTokensPerUser {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":     "Maximum number of tokens reached",
				"code":      "TOO_MANY_TOKENS",
				"limit":     maxTokensPerUser,
				"current":   tokenCount,
			})
			return
		}

		// Calculate expiration with validation
		var expiresAt *time.Time
		if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
			if *req.ExpiresInDays > maxTokenExpirationDays {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "Token expiration exceeds maximum allowed",
					"code":  "EXPIRATION_TOO_LONG",
					"max_days": maxTokenExpirationDays,
				})
				return
			}
			t := time.Now().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
			expiresAt = &t
		}

		// Generate token
		fullToken, prefix, err := utils.GenerateAPIToken()
		if err != nil {
			slog.Error("failed to generate API token", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Hash token for storage
		tokenHash := utils.HashAPIToken(fullToken)
		scopeStr := utils.ScopesToString(req.Scopes)
		clientIP := getClientIPWithConfig(r, cfg)

		// Store in database
		apiToken, err := database.CreateAPIToken(db, user.ID, req.Name, tokenHash, prefix, scopeStr, clientIP, expiresAt)
		if err != nil {
			slog.Error("failed to create API token", "error", err, "user_id", user.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("API token created",
			"token_id", apiToken.ID,
			"user_id", user.ID,
			"username", user.Username,
			"name", req.Name,
			"scopes", scopeStr,
			"expires_at", expiresAt,
			"ip", clientIP,
		)

		// Return response with the full token (shown only once!)
		response := models.CreateAPITokenResponse{
			ID:          apiToken.ID,
			Name:        apiToken.Name,
			Token:       fullToken, // ONLY time this is returned
			TokenPrefix: prefix,
			Scopes:      req.Scopes,
			ExpiresAt:   expiresAt,
			CreatedAt:   apiToken.CreatedAt,
			Warning:     "Save this token securely - it will not be shown again!",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}
}

// ListAPITokensHandler lists all tokens for the authenticated user
func ListAPITokensHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokens, err := database.GetAPITokensByUserID(db, user.ID)
		if err != nil {
			slog.Error("failed to list API tokens", "error", err, "user_id", user.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Ensure we return empty array instead of null
		if tokens == nil {
			tokens = []models.APITokenListItem{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tokens": tokens,
		})
	}
}

// RevokeAPITokenHandler revokes a token owned by the authenticated user
// Tokens can only be revoked via session auth (security: compromised tokens can't revoke others)
func RevokeAPITokenHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Only allow token revocation via session auth (security: compromised tokens can't revoke others)
		authType := middleware.GetAuthTypeFromContext(r)
		if authType != middleware.AuthTypeSession {
			slog.Warn("API token revocation attempted via API token",
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Token revocation requires session authentication (login via web)",
				"code":  "SESSION_REQUIRED",
			})
			return
		}

		// Parse token ID from query parameter or path
		tokenIDStr := r.URL.Query().Get("id")
		if tokenIDStr == "" {
			// Try to get from path: /api/tokens/123
			parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
			if len(parts) > 0 {
				tokenIDStr = parts[len(parts)-1]
			}
		}

		tokenID, err := strconv.ParseInt(tokenIDStr, 10, 64)
		if err != nil || tokenID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid token ID",
				"code":  "INVALID_TOKEN_ID",
			})
			return
		}

		err = database.RevokeAPIToken(db, tokenID, user.ID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Token not found or does not belong to you",
					"code":  "TOKEN_NOT_FOUND",
				})
				return
			}
			slog.Error("failed to revoke API token", "error", err, "token_id", tokenID, "user_id", user.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("API token revoked",
			"token_id", tokenID,
			"user_id", user.ID,
			"username", user.Username,
			"ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Token revoked successfully",
		})
	}
}

// AdminListAPITokensHandler lists all API tokens (admin only)
func AdminListAPITokensHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse pagination
		limit := 50
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
				limit = parsed
			}
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		tokens, total, err := database.GetAllAPITokensAdmin(db, limit, offset)
		if err != nil {
			slog.Error("failed to list API tokens (admin)", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Ensure we return empty array instead of null
		if tokens == nil {
			tokens = []models.APITokenListItem{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tokens": tokens,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
	}
}

// AdminRevokeAPITokenHandler revokes any API token (admin only)
func AdminRevokeAPITokenHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tokenIDStr := r.URL.Query().Get("id")
		tokenID, err := strconv.ParseInt(tokenIDStr, 10, 64)
		if err != nil || tokenID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid token ID",
				"code":  "INVALID_TOKEN_ID",
			})
			return
		}

		// Get token info for logging
		token, _ := database.GetAPITokenByID(db, tokenID)

		err = database.RevokeAPITokenAdmin(db, tokenID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Token not found",
					"code":  "TOKEN_NOT_FOUND",
				})
				return
			}
			slog.Error("failed to revoke API token (admin)", "error", err, "token_id", tokenID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("API token revoked by admin",
			"token_id", tokenID,
			"token_owner_id", func() int64 { if token != nil { return token.UserID } else { return 0 } }(),
			"ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Token revoked successfully",
		})
	}
}
