package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
)

// UserLoginHandler handles user login
func UserLoginHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Parse JSON request
		var req models.UserLoginRequest
		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

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

		// Get user from repository
		user, err := repos.Users.GetByUsername(ctx, req.Username)
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

		// Store session in repository
		err = repos.Users.CreateSession(ctx, user.ID, sessionToken, expiresAt, clientIP, userAgent)
		if err != nil {
			slog.Error("failed to create user session", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Update last login timestamp
		if err := repos.Users.UpdateLastLogin(ctx, user.ID); err != nil {
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

		// Set user CSRF cookie for MFA and other protected user operations
		if _, err := middleware.SetUserCSRFCookie(w, cfg); err != nil {
			slog.Error("failed to set user CSRF cookie", "error", err)
			// Continue anyway - not critical for login success
		}

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
func UserLogoutHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

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

		// Delete session from repository
		if err := repos.Users.DeleteSession(ctx, cookie.Value); err != nil {
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
func UserChangePasswordHandler(repos *repository.Repositories) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context (set by middleware)
		user := middleware.GetUserFromContext(r)
		if user == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Limit JSON request body size to prevent memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

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

		// Update password and invalidate all sessions atomically
		if err := repos.Users.UpdatePasswordWithSessionInvalidation(ctx, user.ID, hashedPassword, true); err != nil {
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
func UserGetCurrentHandler(repos *repository.Repositories) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Get user from context (set by middleware)
		contextUser := middleware.GetUserFromContext(r)
		if contextUser == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Reload user from repository to get fresh data (e.g., after password change)
		user, err := repos.Users.GetByID(ctx, contextUser.ID)
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

