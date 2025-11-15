package testutil

import (
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// SampleUser returns a test user with default values
func SampleUser() *models.User {
	return &models.User{
		ID:                    1,
		Username:              "testuser",
		Email:                 "test@example.com",
		Role:                  "user",
		IsApproved:            true,
		IsActive:              true,
		RequirePasswordChange: false,
		CreatedAt:             time.Now(),
	}
}

// SampleAdmin returns a test admin user
func SampleAdmin() *models.User {
	return &models.User{
		ID:                    2,
		Username:              "admin",
		Email:                 "admin@example.com",
		Role:                  "admin",
		IsApproved:            true,
		IsActive:              true,
		RequirePasswordChange: false,
		CreatedAt:             time.Now(),
	}
}

// SampleFile returns a test file record with default values
func SampleFile() *models.File {
	now := time.Now()
	maxDownloads := 5

	return &models.File{
		ID:               1,
		ClaimCode:        "test-claim-code",
		OriginalFilename: "test.txt",
		StoredFilename:   "uuid-test.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		CreatedAt:        now,
		ExpiresAt:        now.Add(24 * time.Hour),
		MaxDownloads:     &maxDownloads,
		DownloadCount:    0,
		UploaderIP:       "127.0.0.1",
		PasswordHash:     "",
		UserID:           nil,
	}
}

// SampleFileWithPassword returns a test file with password protection
func SampleFileWithPassword() *models.File {
	file := SampleFile()
	// bcrypt hash of "password123"
	file.PasswordHash = "$2a$10$YourHashHere"
	return file
}

// SamplePartialUpload returns a test partial upload record
func SamplePartialUpload() *models.PartialUpload {
	now := time.Now()

	return &models.PartialUpload{
		UploadID:       "test-upload-id",
		Filename:       "large-file.zip",
		TotalSize:      100 * 1024 * 1024, // 100MB
		ChunkSize:      10 * 1024 * 1024,  // 10MB
		TotalChunks:    10,
		ChunksReceived: 0,
		ReceivedBytes:  0,
		ExpiresInHours: 24,
		MaxDownloads:   5,
		Completed:      false,
		CreatedAt:      now,
		LastActivity:   now,
		UserID:         nil,
		Status:         "uploading",
	}
}
