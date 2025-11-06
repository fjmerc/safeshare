package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

// UserLoginHandler handles user login
func UserLoginHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse JSON request
		var req models.UserLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse login request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		clientIP := getClientIP(r)
		userAgent := getUserAgent(r)

		// Validate input
		if req.Username == "" || req.Password == "" {
			slog.Warn("user login failed - empty username or password",
				"username", req.Username,
				"ip", clientIP,
			)
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid username or password",
			})
			return
		}

		// Get user from database
		user, err := database.GetUserByUsername(db, req.Username)
		if err != nil {
			slog.Error("failed to get user", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Check if user exists and password matches
		if user == nil || !utils.VerifyPassword(user.PasswordHash, req.Password) {
			slog.Warn("user login failed - invalid credentials",
				"username", req.Username,
				"ip", clientIP,
			)
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid username or password",
			})
			return
		}

		// Check if user is active
		if !user.IsActive {
			slog.Warn("user login failed - account disabled",
				"username", req.Username,
				"ip", clientIP,
			)
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Account has been disabled",
			})
			return
		}

		// Generate session token
		sessionToken, err := utils.GenerateSessionToken()
		if err != nil {
			slog.Error("failed to generate session token", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Calculate expiry time (use same as admin session)
		expiresAt := time.Now().Add(time.Duration(cfg.SessionExpiryHours) * time.Hour)

		// Store session in database
		err = database.CreateUserSession(db, user.ID, sessionToken, expiresAt, clientIP, userAgent)
		if err != nil {
			slog.Error("failed to create user session", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Update last login timestamp
		if err := database.UpdateUserLastLogin(db, user.ID); err != nil {
			slog.Error("failed to update last login", "error", err)
			// Don't fail the request, just log
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "user_session",
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.HTTPSEnabled,
			SameSite: http.SameSiteStrictMode,
			Expires:  expiresAt,
		})

		slog.Info("user login successful",
			"username", req.Username,
			"user_id", user.ID,
			"ip", clientIP,
		)

		// Return user info (without password hash)
		response := models.UserLoginResponse{
			ID:                    user.ID,
			Username:              user.Username,
			Email:                 user.Email,
			Role:                  user.Role,
			RequirePasswordChange: user.RequirePasswordChange,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// UserLogoutHandler handles user logout
func UserLogoutHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get session token from cookie
		cookie, err := r.Cookie("user_session")
		if err != nil {
			// No session cookie, already logged out
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"message": "Logged out successfully",
			})
			return
		}

		// Delete session from database
		if err := database.DeleteUserSession(db, cookie.Value); err != nil {
			slog.Error("failed to delete user session", "error", err)
			// Continue anyway to clear the cookie
		}

		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "user_session",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.HTTPSEnabled,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
		})

		slog.Info("user logout successful",
			"ip", getClientIP(r),
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Logged out successfully",
		})
	}
}

// UserChangePasswordHandler handles user password changes
func UserChangePasswordHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user from context (set by middleware)
		user := r.Context().Value("user").(*models.User)

		// Parse request
		var req models.ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse change password request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate input
		if req.CurrentPassword == "" || req.NewPassword == "" || req.ConfirmPassword == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "All fields are required",
			})
			return
		}

		// Check if new passwords match
		if req.NewPassword != req.ConfirmPassword {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "New passwords do not match",
			})
			return
		}

		// Verify current password
		if !utils.VerifyPassword(user.PasswordHash, req.CurrentPassword) {
			slog.Warn("password change failed - incorrect current password",
				"user_id", user.ID,
				"username", user.Username,
			)
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Current password is incorrect",
			})
			return
		}

		// Validate new password strength (basic check)
		if len(req.NewPassword) < 8 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "New password must be at least 8 characters long",
			})
			return
		}

		// Hash new password
		hashedPassword, err := utils.HashPassword(req.NewPassword)
		if err != nil {
			slog.Error("failed to hash password", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Update password in database
		if err := database.UpdateUserPassword(db, user.ID, hashedPassword, true); err != nil {
			slog.Error("failed to update password", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("password changed successfully",
			"user_id", user.ID,
			"username", user.Username,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Password changed successfully",
		})
	}
}

// UserGetCurrentHandler returns the current logged-in user info
func UserGetCurrentHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user from context (set by middleware)
		contextUser := r.Context().Value("user").(*models.User)

		// Reload user from database to get fresh data (e.g., after password change)
		user, err := database.GetUserByID(db, contextUser.ID)
		if err != nil || user == nil {
			slog.Error("failed to get user", "error", err, "user_id", contextUser.ID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := models.UserLoginResponse{
			ID:                    user.ID,
			Username:              user.Username,
			Email:                 user.Email,
			Role:                  user.Role,
			RequirePasswordChange: user.RequirePasswordChange,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// Helper function to get client IP (supporting X-Forwarded-For and X-Real-IP)
func getUserIP(r *http.Request) string {
	// Try X-Forwarded-For first (for proxies/load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Try X-Real-IP next
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
