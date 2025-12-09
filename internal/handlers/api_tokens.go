package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// tokenRotatePathRegex matches /api/tokens/{id}/rotate where id is numeric
var tokenRotatePathRegex = regexp.MustCompile(`^/api/tokens/([0-9]+)/rotate/?$`)

// CreateAPITokenHandler creates a new API token for the authenticated user.
// Uses the repository pattern for database access and enforces configurable token limits.
// Tokens can only be created via session auth (not via existing API token).
func CreateAPITokenHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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

		// Get configurable limits from config
		maxTokensPerUser := cfg.APIToken.MaxTokensPerUser
		maxExpiryDays := cfg.APIToken.MaxExpiryDays

		// Calculate expiration with validation
		var expiresAt *time.Time
		if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
			if *req.ExpiresInDays > maxExpiryDays {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":    "Token expiration exceeds maximum allowed",
					"code":     "EXPIRATION_TOO_LONG",
					"max_days": maxExpiryDays,
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

		// Store in database using atomic CreateWithLimit to prevent race conditions
		// This uses a transaction to ensure count check and insert are atomic
		apiToken, err := repos.APITokens.CreateWithLimit(ctx, user.ID, req.Name, tokenHash, prefix, scopeStr, clientIP, expiresAt, maxTokensPerUser)
		if err != nil {
			if errors.Is(err, repository.ErrTooManyTokens) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": "Maximum number of tokens reached",
					"code":  "TOO_MANY_TOKENS",
					"limit": maxTokensPerUser,
				})
				return
			}
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
// Deprecated: Use ListAPITokensWithStatsHandler for usage statistics support.
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

// ListAPITokensWithStatsHandler lists all tokens for the authenticated user with usage statistics.
// Uses the repository pattern for database access and includes usage stats for each token.
func ListAPITokensWithStatsHandler(repos *repository.Repositories) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokens, err := repos.APITokens.GetByUserID(ctx, user.ID)
		if err != nil {
			slog.Error("failed to list API tokens", "error", err, "user_id", user.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Ensure we return empty array instead of null
		if tokens == nil {
			tokens = []models.APITokenListItem{}
		}

		// Collect token IDs for batch stats query
		tokenIDs := make([]int64, len(tokens))
		for i, token := range tokens {
			tokenIDs[i] = token.ID
		}

		// Batch fetch usage stats for all tokens (avoids N+1 query problem)
		statsMap, err := repos.APITokens.GetUsageStatsBatch(ctx, tokenIDs)
		if err != nil {
			slog.Warn("failed to get batch usage stats", "error", err, "user_id", user.ID)
			// Initialize empty map if batch query fails
			statsMap = make(map[int64]*models.TokenUsageStats)
		}

		// Build response with usage stats for each token
		tokensWithStats := make([]models.APITokenWithStats, 0, len(tokens))
		for _, token := range tokens {
			tokenWithStats := models.APITokenWithStats{
				APITokenListItem: token,
			}

			// Get stats from batch result
			if stats, ok := statsMap[token.ID]; ok {
				tokenWithStats.UsageStats = stats
			}

			tokensWithStats = append(tokensWithStats, tokenWithStats)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tokens": tokensWithStats,
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

// RotateTokenHandler regenerates an API token while preserving its metadata.
// The old token is immediately invalidated and a new token is generated.
// Tokens can only be rotated via session auth (security: compromised tokens can't rotate themselves).
func RotateTokenHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Only allow token rotation via session auth (security: compromised tokens can't rotate themselves)
		authType := middleware.GetAuthTypeFromContext(r)
		if authType != middleware.AuthTypeSession {
			slog.Warn("API token rotation attempted via API token",
				"user_id", user.ID,
				"username", user.Username,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Token rotation requires session authentication (login via web)",
				"code":  "SESSION_REQUIRED",
			})
			return
		}

		// Parse token ID from path using regex: /api/tokens/{id}/rotate
		matches := tokenRotatePathRegex.FindStringSubmatch(r.URL.Path)
		if len(matches) != 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request path",
				"code":  "INVALID_PATH",
			})
			return
		}

		tokenID, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil || tokenID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid token ID",
				"code":  "INVALID_TOKEN_ID",
			})
			return
		}

		// Generate new token
		newToken, newPrefix, err := utils.GenerateAPIToken()
		if err != nil {
			slog.Error("failed to generate new API token", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Hash the new token
		newHash := utils.HashAPIToken(newToken)

		// Rotate the token in the database
		updatedToken, err := repos.APITokens.Rotate(ctx, tokenID, user.ID, newHash, newPrefix)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Token not found or does not belong to you",
					"code":  "TOKEN_NOT_FOUND",
				})
				return
			}
			slog.Error("failed to rotate API token",
				"error", err,
				"token_id", tokenID,
				"user_id", user.ID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("API token rotated",
			"token_id", tokenID,
			"user_id", user.ID,
			"username", user.Username,
			"new_prefix", newPrefix,
			"ip", getClientIPWithConfig(r, cfg),
		)

		// Convert scopes string to slice
		scopes := utils.StringToScopes(updatedToken.Scopes)

		// Return the new token (shown only once!)
		response := models.RotateAPITokenResponse{
			ID:          updatedToken.ID,
			Name:        updatedToken.Name,
			Token:       newToken, // New token - shown only once!
			TokenPrefix: newPrefix,
			Scopes:      scopes,
			ExpiresAt:   updatedToken.ExpiresAt,
			CreatedAt:   updatedToken.CreatedAt,
			RotatedAt:   time.Now(),
			Warning:     "Save this token securely - it will not be shown again! The previous token has been invalidated.",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// AdminListAPITokensHandler lists all API tokens (admin only)
// Deprecated: Use AdminListAPITokensWithStatsHandler for usage statistics support.
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

// AdminListAPITokensWithStatsHandler lists all API tokens with usage statistics (admin only).
// Uses the repository pattern for database access and includes usage stats for each token.
func AdminListAPITokensWithStatsHandler(repos *repository.Repositories) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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

		tokens, total, err := repos.APITokens.GetAllAdmin(ctx, limit, offset)
		if err != nil {
			slog.Error("failed to list API tokens (admin)", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Ensure we return empty array instead of null
		if tokens == nil {
			tokens = []models.APITokenListItem{}
		}

		// Collect token IDs for batch stats query
		tokenIDs := make([]int64, len(tokens))
		for i, token := range tokens {
			tokenIDs[i] = token.ID
		}

		// Batch fetch usage stats for all tokens (avoids N+1 query problem)
		statsMap, err := repos.APITokens.GetUsageStatsBatch(ctx, tokenIDs)
		if err != nil {
			slog.Warn("failed to get batch usage stats (admin)", "error", err)
			// Initialize empty map if batch query fails
			statsMap = make(map[int64]*models.TokenUsageStats)
		}

		// Build response with usage stats for each token
		tokensWithStats := make([]models.APITokenWithStats, 0, len(tokens))
		for _, token := range tokens {
			tokenWithStats := models.APITokenWithStats{
				APITokenListItem: token,
			}

			// Get stats from batch result
			if stats, ok := statsMap[token.ID]; ok {
				tokenWithStats.UsageStats = stats
			}

			tokensWithStats = append(tokensWithStats, tokenWithStats)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tokens": tokensWithStats,
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
			"token_owner_id", func() int64 {
				if token != nil {
					return token.UserID
				} else {
					return 0
				}
			}(),
			"ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Token revoked successfully",
		})
	}
}
