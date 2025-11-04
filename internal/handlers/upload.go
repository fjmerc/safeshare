package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/yourusername/safeshare/internal/config"
	"github.com/yourusername/safeshare/internal/database"
	"github.com/yourusername/safeshare/internal/models"
	"github.com/yourusername/safeshare/internal/utils"
)

// UploadHandler handles file upload requests
func UploadHandler(db *sql.DB, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only accept POST requests
		if r.Method != http.MethodPost {
			sendError(w, "Method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
			return
		}

		// Parse multipart form with size limit
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxFileSize)
		if err := r.ParseMultipartForm(cfg.MaxFileSize); err != nil {
			sendError(w, "File too large or invalid form data", "FILE_TOO_LARGE", http.StatusRequestEntityTooLarge)
			return
		}

		// Get the file from the form
		file, header, err := r.FormFile("file")
		if err != nil {
			sendError(w, "No file provided", "NO_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Validate file size
		if header.Size > cfg.MaxFileSize {
			sendError(w, fmt.Sprintf("File size exceeds maximum of %d bytes", cfg.MaxFileSize), "FILE_TOO_LARGE", http.StatusRequestEntityTooLarge)
			return
		}

		// Parse optional parameters
		expiresInHours := cfg.DefaultExpirationHours
		if hoursStr := r.FormValue("expires_in_hours"); hoursStr != "" {
			hours, err := strconv.ParseFloat(hoursStr, 64)
			if err != nil || hours <= 0 {
				sendError(w, "Invalid expires_in_hours parameter", "INVALID_PARAMETER", http.StatusBadRequest)
				return
			}
			expiresInHours = int(hours * 60) // Convert to minutes for precision
			if expiresInHours < 1 {
				expiresInHours = 1 // Minimum 1 minute
			}
		} else {
			expiresInHours = cfg.DefaultExpirationHours * 60 // Convert to minutes
		}

		var maxDownloads *int
		if maxDownloadsStr := r.FormValue("max_downloads"); maxDownloadsStr != "" {
			maxDl, err := strconv.Atoi(maxDownloadsStr)
			if err != nil || maxDl <= 0 {
				sendError(w, "Invalid max_downloads parameter", "INVALID_PARAMETER", http.StatusBadRequest)
				return
			}
			maxDownloads = &maxDl
		}

		// Generate unique claim code (with retry on collision)
		var claimCode string
		maxRetries := 5
		for i := 0; i < maxRetries; i++ {
			claimCode, err = utils.GenerateClaimCode()
			if err != nil {
				slog.Error("failed to generate claim code", "error", err)
				sendError(w, "Failed to generate claim code", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			// Check if code already exists
			existing, err := database.GetFileByClaimCode(db, claimCode)
			if err != nil {
				slog.Error("failed to check claim code", "error", err)
				sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}

			if existing == nil {
				break // Code is unique
			}

			if i == maxRetries-1 {
				sendError(w, "Failed to generate unique claim code", "INTERNAL_ERROR", http.StatusInternalServerError)
				return
			}
		}

		// Generate unique filename for storage
		storedFilename := uuid.New().String() + filepath.Ext(header.Filename)

		// Create upload directory if it doesn't exist
		if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
			slog.Error("failed to create upload directory", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Save file to disk
		filePath := filepath.Join(cfg.UploadDir, storedFilename)
		destFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			slog.Error("failed to create file", "path", filePath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		defer destFile.Close()

		written, err := io.Copy(destFile, file)
		if err != nil {
			os.Remove(filePath) // Clean up on error
			slog.Error("failed to write file", "path", filePath, "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Get client IP
		clientIP := getClientIP(r)

		// Create database record
		expiresAt := time.Now().Add(time.Duration(expiresInHours) * time.Minute)
		fileRecord := &models.File{
			ClaimCode:        claimCode,
			OriginalFilename: header.Filename,
			StoredFilename:   storedFilename,
			FileSize:         written,
			MimeType:         header.Header.Get("Content-Type"),
			ExpiresAt:        expiresAt,
			MaxDownloads:     maxDownloads,
			UploaderIP:       clientIP,
		}

		if err := database.CreateFile(db, fileRecord); err != nil {
			os.Remove(filePath) // Clean up on error
			slog.Error("failed to create file record", "error", err)
			sendError(w, "Internal server error", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}

		// Build download URL (respects reverse proxy headers and PUBLIC_URL config)
		downloadURL := buildDownloadURL(r, cfg, claimCode)

		// Send success response
		response := models.UploadResponse{
			ClaimCode:        claimCode,
			ExpiresAt:        expiresAt,
			DownloadURL:      downloadURL,
			MaxDownloads:     maxDownloads,
			FileSize:         written,
			OriginalFilename: header.Filename,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)

		slog.Info("file uploaded",
			"claim_code", claimCode,
			"filename", header.Filename,
			"size", written,
			"expires_at", expiresAt,
		)
	}
}

// sendError sends a JSON error response
func sendError(w http.ResponseWriter, message, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	errResp := models.ErrorResponse{
		Error: message,
		Code:  code,
	}

	json.NewEncoder(w).Encode(errResp)
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}
