package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/yourusername/safeshare/internal/database"
	"github.com/yourusername/safeshare/internal/models"
	"github.com/yourusername/safeshare/internal/utils"
)

// AdminCreateUserHandler handles admin user creation (invite-only registration)
func AdminCreateUserHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request
		var req models.CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse create user request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Validate input
		if req.Username == "" || req.Email == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Username and email are required",
			})
			return
		}

		// Validate username (alphanumeric, underscore, dash only)
		for _, c := range req.Username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				 (c >= '0' && c <= '9') || c == '_' || c == '-') {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Username can only contain letters, numbers, underscore, and dash",
				})
				return
			}
		}

		// Validate email format (basic check)
		if !strings.Contains(req.Email, "@") || !strings.Contains(req.Email, ".") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid email format",
			})
			return
		}

		// Check if username already exists
		existingUser, err := database.GetUserByUsername(db, req.Username)
		if err != nil {
			slog.Error("failed to check existing username", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if existingUser != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Username already exists",
			})
			return
		}

		// Generate temporary password if not provided
		temporaryPassword := req.Password
		if temporaryPassword == "" {
			temporaryPassword, err = utils.GenerateTemporaryPassword()
			if err != nil {
				slog.Error("failed to generate temporary password", "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		// Hash password
		hashedPassword, err := utils.HashPassword(temporaryPassword)
		if err != nil {
			slog.Error("failed to hash password", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Create user in database
		user, err := database.CreateUser(db, req.Username, req.Email, hashedPassword, "user", true)
		if err != nil {
			slog.Error("failed to create user", "error", err)

			// Check if it's a unique constraint violation
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Username or email already exists",
				})
				return
			}

			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin created new user",
			"admin_ip", getClientIP(r),
			"new_user_id", user.ID,
			"username", user.Username,
		)

		// Return user info with temporary password
		response := models.CreateUserResponse{
			ID:               user.ID,
			Username:         user.Username,
			Email:            user.Email,
			TemporaryPassword: temporaryPassword,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}
}

// AdminListUsersHandler returns paginated list of users
func AdminListUsersHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse pagination parameters
		limitStr := r.URL.Query().Get("limit")
		offsetStr := r.URL.Query().Get("offset")

		limit := 50 // default
		offset := 0

		if limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
				limit = l
			}
		}

		if offsetStr != "" {
			if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
				offset = o
			}
		}

		// Get users from database
		users, total, err := database.GetAllUsers(db, limit, offset)
		if err != nil {
			slog.Error("failed to get users", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"users":  users,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// AdminUpdateUserHandler handles updating user details
func AdminUpdateUserHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPatch {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user ID from URL path
		path := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
		userIDStr := strings.Split(path, "/")[0]
		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid user ID",
			})
			return
		}

		// Parse request
		var req models.UpdateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			slog.Error("failed to parse update user request", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request format",
			})
			return
		}

		// Get existing user
		user, err := database.GetUserByID(db, userID)
		if err != nil {
			slog.Error("failed to get user", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if user == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "User not found",
			})
			return
		}

		// Use existing values if not provided in request
		username := req.Username
		if username == "" {
			username = user.Username
		}

		email := req.Email
		if email == "" {
			email = user.Email
		}

		role := req.Role
		if role == "" {
			role = user.Role
		} else if role != "user" && role != "admin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Role must be 'user' or 'admin'",
			})
			return
		}

		// Update user in database
		if err := database.UpdateUser(db, userID, username, email, role); err != nil {
			slog.Error("failed to update user", "error", err)

			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Username or email already exists",
				})
				return
			}

			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin updated user",
			"admin_ip", getClientIP(r),
			"user_id", userID,
			"username", username,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User updated successfully",
		})
	}
}

// AdminToggleUserActiveHandler enables or disables a user account
func AdminToggleUserActiveHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user ID from URL path
		path := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
		parts := strings.Split(path, "/")
		if len(parts) < 2 {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		userIDStr := parts[0]
		action := parts[1]

		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid user ID",
			})
			return
		}

		// Determine if enabling or disabling
		var isActive bool
		if action == "enable" {
			isActive = true
		} else if action == "disable" {
			isActive = false
		} else {
			http.Error(w, "Invalid action", http.StatusBadRequest)
			return
		}

		// Check if user exists
		user, err := database.GetUserByID(db, userID)
		if err != nil {
			slog.Error("failed to get user", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if user == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "User not found",
			})
			return
		}

		// Update user active status
		if err := database.SetUserActive(db, userID, isActive); err != nil {
			slog.Error("failed to toggle user active status", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin toggled user active status",
			"admin_ip", getClientIP(r),
			"user_id", userID,
			"username", user.Username,
			"is_active", isActive,
		)

		message := "User disabled successfully"
		if isActive {
			message = "User enabled successfully"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": message,
		})
	}
}

// AdminResetUserPasswordHandler generates a new temporary password for a user
func AdminResetUserPasswordHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user ID from URL path
		path := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
		parts := strings.Split(path, "/")
		if len(parts) < 2 {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}

		userIDStr := parts[0]
		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid user ID",
			})
			return
		}

		// Check if user exists
		user, err := database.GetUserByID(db, userID)
		if err != nil {
			slog.Error("failed to get user", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if user == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "User not found",
			})
			return
		}

		// Generate temporary password
		temporaryPassword, err := utils.GenerateTemporaryPassword()
		if err != nil {
			slog.Error("failed to generate temporary password", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Hash password
		hashedPassword, err := utils.HashPassword(temporaryPassword)
		if err != nil {
			slog.Error("failed to hash password", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Update password in database (set require_password_change flag)
		if err := database.UpdateUserPassword(db, userID, hashedPassword, false); err != nil {
			slog.Error("failed to reset password", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin reset user password",
			"admin_ip", getClientIP(r),
			"user_id", userID,
			"username", user.Username,
		)

		response := map[string]string{
			"message":            "Password reset successfully",
			"temporary_password": temporaryPassword,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// AdminDeleteUserHandler deletes a user account
func AdminDeleteUserHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get user ID from URL path
		path := strings.TrimPrefix(r.URL.Path, "/admin/api/users/")
		userIDStr := strings.TrimSuffix(path, "/")
		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid user ID",
			})
			return
		}

		// Check if user exists
		user, err := database.GetUserByID(db, userID)
		if err != nil {
			slog.Error("failed to get user", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if user == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "User not found",
			})
			return
		}

		// Delete user from database
		if err := database.DeleteUser(db, userID); err != nil {
			slog.Error("failed to delete user", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		slog.Info("admin deleted user",
			"admin_ip", getClientIP(r),
			"user_id", userID,
			"username", user.Username,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "User deleted successfully",
		})
	}
}
