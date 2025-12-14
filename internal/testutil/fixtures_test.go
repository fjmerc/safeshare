package testutil

import (
	"testing"
	"time"
)

func TestSampleUser(t *testing.T) {
	user := SampleUser()

	if user == nil {
		t.Fatal("SampleUser returned nil")
	}
	if user.ID != 1 {
		t.Errorf("expected ID 1, got %d", user.ID)
	}
	if user.Username != "testuser" {
		t.Errorf("expected username testuser, got %s", user.Username)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", user.Email)
	}
	if user.Role != "user" {
		t.Errorf("expected role user, got %s", user.Role)
	}
	if !user.IsApproved {
		t.Error("expected IsApproved to be true")
	}
	if !user.IsActive {
		t.Error("expected IsActive to be true")
	}
	if user.RequirePasswordChange {
		t.Error("expected RequirePasswordChange to be false")
	}
	if user.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
}

func TestSampleAdmin(t *testing.T) {
	admin := SampleAdmin()

	if admin == nil {
		t.Fatal("SampleAdmin returned nil")
	}
	if admin.ID != 2 {
		t.Errorf("expected ID 2, got %d", admin.ID)
	}
	if admin.Username != "admin" {
		t.Errorf("expected username admin, got %s", admin.Username)
	}
	if admin.Email != "admin@example.com" {
		t.Errorf("expected email admin@example.com, got %s", admin.Email)
	}
	if admin.Role != "admin" {
		t.Errorf("expected role admin, got %s", admin.Role)
	}
	if !admin.IsApproved {
		t.Error("expected IsApproved to be true")
	}
	if !admin.IsActive {
		t.Error("expected IsActive to be true")
	}
}

func TestSampleFile(t *testing.T) {
	file := SampleFile()

	if file == nil {
		t.Fatal("SampleFile returned nil")
	}
	if file.ID != 1 {
		t.Errorf("expected ID 1, got %d", file.ID)
	}
	if file.ClaimCode != "test-claim-code" {
		t.Errorf("expected claim code test-claim-code, got %s", file.ClaimCode)
	}
	if file.OriginalFilename != "test.txt" {
		t.Errorf("expected filename test.txt, got %s", file.OriginalFilename)
	}
	if file.StoredFilename != "uuid-test.txt" {
		t.Errorf("expected stored filename uuid-test.txt, got %s", file.StoredFilename)
	}
	if file.FileSize != 1024 {
		t.Errorf("expected size 1024, got %d", file.FileSize)
	}
	if file.MimeType != "text/plain" {
		t.Errorf("expected mime text/plain, got %s", file.MimeType)
	}
	if file.MaxDownloads == nil || *file.MaxDownloads != 5 {
		t.Error("expected MaxDownloads to be 5")
	}
	if file.DownloadCount != 0 {
		t.Errorf("expected download count 0, got %d", file.DownloadCount)
	}
	if file.UploaderIP != "127.0.0.1" {
		t.Errorf("expected uploader IP 127.0.0.1, got %s", file.UploaderIP)
	}
	if file.PasswordHash != "" {
		t.Error("expected empty password hash")
	}
	if file.UserID != nil {
		t.Error("expected nil UserID")
	}
	if file.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if file.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
}

func TestSampleFileWithPassword(t *testing.T) {
	file := SampleFileWithPassword()

	if file == nil {
		t.Fatal("SampleFileWithPassword returned nil")
	}
	if file.PasswordHash == "" {
		t.Error("expected non-empty password hash")
	}
	// Verify it's based on SampleFile
	if file.ClaimCode != "test-claim-code" {
		t.Error("should inherit from SampleFile")
	}
}

func TestSamplePartialUpload(t *testing.T) {
	upload := SamplePartialUpload()

	if upload == nil {
		t.Fatal("SamplePartialUpload returned nil")
	}
	if upload.UploadID != "test-upload-id" {
		t.Errorf("expected upload ID test-upload-id, got %s", upload.UploadID)
	}
	if upload.Filename != "large-file.zip" {
		t.Errorf("expected filename large-file.zip, got %s", upload.Filename)
	}
	if upload.TotalSize != 100*1024*1024 {
		t.Errorf("expected total size 100MB, got %d", upload.TotalSize)
	}
	if upload.ChunkSize != 10*1024*1024 {
		t.Errorf("expected chunk size 10MB, got %d", upload.ChunkSize)
	}
	if upload.TotalChunks != 10 {
		t.Errorf("expected 10 total chunks, got %d", upload.TotalChunks)
	}
	if upload.ChunksReceived != 0 {
		t.Errorf("expected 0 chunks received, got %d", upload.ChunksReceived)
	}
	if upload.ReceivedBytes != 0 {
		t.Errorf("expected 0 received bytes, got %d", upload.ReceivedBytes)
	}
	if upload.ExpiresInHours != 24 {
		t.Errorf("expected 24 expiry hours, got %d", upload.ExpiresInHours)
	}
	if upload.MaxDownloads != 5 {
		t.Errorf("expected 5 max downloads, got %d", upload.MaxDownloads)
	}
	if upload.Completed {
		t.Error("expected Completed to be false")
	}
	if upload.Status != "uploading" {
		t.Errorf("expected status uploading, got %s", upload.Status)
	}
	if upload.UserID != nil {
		t.Error("expected nil UserID")
	}
	if upload.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if upload.LastActivity.IsZero() {
		t.Error("LastActivity should be set")
	}
}
