package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

func TestUploadInitHandler_ValidRequest(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadInitHandler(db, cfg)

	// Create init request
	initReq := models.UploadInitRequest{
		Filename:       "testfile.txt",
		TotalSize:      1024 * 1024, // 1 MB
		ExpiresInHours: 24,
		MaxDownloads:   5,
		Password:       "",
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var response models.UploadInitResponse
	json.NewDecoder(rr.Body).Decode(&response)

	if response.UploadID == "" {
		t.Error("upload_id should not be empty")
	}

	if response.ChunkSize <= 0 {
		t.Error("chunk_size should be positive")
	}

	if response.TotalChunks <= 0 {
		t.Error("total_chunks should be positive")
	}

	// Verify partial upload created in database
	partialUpload, _ := database.GetPartialUpload(db, response.UploadID)
	if partialUpload == nil {
		t.Error("partial upload should be created in database")
	}
}

func TestUploadInitHandler_ChunkedUploadDisabled(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = false // Disable chunked uploads

	handler := UploadInitHandler(db, cfg)

	initReq := models.UploadInitRequest{
		Filename:  "test.txt",
		TotalSize: 1024,
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 503 Service Unavailable
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestUploadInitHandler_BlockedExtension(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadInitHandler(db, cfg)

	// Try to upload blocked extension
	initReq := models.UploadInitRequest{
		Filename:  "malware.exe",
		TotalSize: 1024,
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if errorCode, ok := response["code"].(string); !ok || errorCode != "BLOCKED_EXTENSION" {
		t.Errorf("code = %v, want BLOCKED_EXTENSION", response["code"])
	}
}

func TestUploadInitHandler_FileTooLarge(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Set max file size to 1 MB
	cfg.SetMaxFileSize(1024 * 1024)

	handler := UploadInitHandler(db, cfg)

	// Try to upload 10 MB file
	initReq := models.UploadInitRequest{
		Filename:  "largefile.bin",
		TotalSize: 10 * 1024 * 1024, // 10 MB
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 413 Request Entity Too Large
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestUploadInitHandler_InvalidTotalSize(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadInitHandler(db, cfg)

	// Zero total size
	initReq := models.UploadInitRequest{
		Filename:  "test.txt",
		TotalSize: 0,
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUploadInitHandler_MissingFilename(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadInitHandler(db, cfg)

	initReq := models.UploadInitRequest{
		Filename:  "", // Missing filename
		TotalSize: 1024,
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUploadInitHandler_WithPassword(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadInitHandler(db, cfg)

	initReq := models.UploadInitRequest{
		Filename:  "secret.txt",
		TotalSize: 1024,
		Password:  "securepassword123",
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var response models.UploadInitResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify password is hashed in database
	partialUpload, _ := database.GetPartialUpload(db, response.UploadID)
	if partialUpload.PasswordHash == "" {
		t.Error("password_hash should not be empty")
	}

	// Verify hash is bcrypt
	if !utils.VerifyPassword(partialUpload.PasswordHash, "securepassword123") {
		t.Error("password should be properly hashed")
	}
}

func TestUploadChunkHandler_ValidChunk(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload first (use valid UUID)
	uploadID := "550e8400-e29b-41d4-a716-446655440001"
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "test.txt",
		TotalSize:    2048,
		ChunkSize:    1024,
		TotalChunks:  2,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	handler := UploadChunkHandler(db, cfg)

	// Create chunk data
	chunkData := bytes.Repeat([]byte("A"), 1024)

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("chunk", "chunk0")
	part.Write(chunkData)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/"+uploadID+"/0", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response models.UploadChunkResponse
	json.NewDecoder(rr.Body).Decode(&response)

	if response.ChunkNumber != 0 {
		t.Errorf("chunk_number = %d, want 0", response.ChunkNumber)
	}

	if response.Checksum == "" {
		t.Error("checksum should not be empty")
	}

	// Verify chunk file exists
	chunkPath := filepath.Join(cfg.UploadDir, ".partial", partialUpload.UploadID, "chunk_0")
	if _, err := os.Stat(chunkPath); os.IsNotExist(err) {
		t.Error("chunk file should exist on disk")
	}
}

func TestUploadChunkHandler_InvalidUploadID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadChunkHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/invalid-id/0", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request for invalid UUID
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUploadChunkHandler_UploadNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadChunkHandler(db, cfg)

	// Valid UUID but doesn't exist
	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/550e8400-e29b-41d4-a716-446655440000/0", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 404 Not Found
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestUploadChunkHandler_ChunkNumberOutOfRange(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload with 2 chunks
	partialUpload := &models.PartialUpload{
		UploadID:     "550e8400-e29b-41d4-a716-446655440002",
		Filename:     "test.txt",
		TotalSize:    2048,
		ChunkSize:    1024,
		TotalChunks:  2,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	handler := UploadChunkHandler(db, cfg)

	// Try to upload chunk 5 (out of range)
	chunkData := bytes.Repeat([]byte("A"), 1024)
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("chunk", "chunk5")
	part.Write(chunkData)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/550e8400-e29b-41d4-a716-446655440002/5", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUploadChunkHandler_ChunkSizeMismatch(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload with 1024 byte chunks
	partialUpload := &models.PartialUpload{
		UploadID:     "550e8400-e29b-41d4-a716-446655440002",
		Filename:     "test.txt",
		TotalSize:    2048,
		ChunkSize:    1024,
		TotalChunks:  2,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	handler := UploadChunkHandler(db, cfg)

	// Upload chunk 0 with wrong size (512 instead of 1024)
	chunkData := bytes.Repeat([]byte("A"), 512)
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("chunk", "chunk0")
	part.Write(chunkData)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/550e8400-e29b-41d4-a716-446655440002/0", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request for size mismatch
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUploadChunkHandler_Idempotency(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload
	partialUpload := &models.PartialUpload{
		UploadID:     "550e8400-e29b-41d4-a716-446655440002",
		Filename:     "test.txt",
		TotalSize:    2048,
		ChunkSize:    1024,
		TotalChunks:  2,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	handler := UploadChunkHandler(db, cfg)

	chunkData := bytes.Repeat([]byte("A"), 1024)

	// Upload chunk 0 first time
	var buf1 bytes.Buffer
	writer1 := multipart.NewWriter(&buf1)
	part1, _ := writer1.CreateFormFile("chunk", "chunk0")
	part1.Write(chunkData)
	writer1.Close()

	req1 := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/550e8400-e29b-41d4-a716-446655440002/0", &buf1)
	req1.Header.Set("Content-Type", writer1.FormDataContentType())
	rr1 := httptest.NewRecorder()

	handler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Errorf("first upload: status = %d, want %d", rr1.Code, http.StatusOK)
	}

	// Upload same chunk again (idempotency test)
	var buf2 bytes.Buffer
	writer2 := multipart.NewWriter(&buf2)
	part2, _ := writer2.CreateFormFile("chunk", "chunk0")
	part2.Write(chunkData)
	writer2.Close()

	req2 := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/550e8400-e29b-41d4-a716-446655440002/0", &buf2)
	req2.Header.Set("Content-Type", writer2.FormDataContentType())
	rr2 := httptest.NewRecorder()

	handler.ServeHTTP(rr2, req2)

	// Should still return 200 OK (idempotent)
	if rr2.Code != http.StatusOK {
		t.Errorf("second upload: status = %d, want %d", rr2.Code, http.StatusOK)
	}
}

func TestUploadCompleteHandler_AllChunksPresent(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload
	uploadID := "550e8400-e29b-41d4-a716-446655440003"
	partialUpload := &models.PartialUpload{
		UploadID:       uploadID,
		Filename:       "complete.txt",
		TotalSize:      2048,
		ChunkSize:      1024,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   0,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	// Create all chunks on disk using the actual upload directory from config
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	if err := os.MkdirAll(partialDir, 0755); err != nil {
		t.Fatalf("Failed to create partial dir: %v", err)
	}

	for i := 0; i < 2; i++ {
		chunkPath := filepath.Join(partialDir, fmt.Sprintf("chunk_%d", i))
		chunkData := bytes.Repeat([]byte("A"), 1024)
		os.WriteFile(chunkPath, chunkData, 0644)
	}

	handler := UploadCompleteHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 202 Accepted (async processing)
	if rr.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if status, ok := response["status"].(string); !ok || status != "processing" {
		t.Errorf("status = %v, want processing", response["status"])
	}
}

func TestUploadCompleteHandler_MissingChunks(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload
	uploadID := "550e8400-e29b-41d4-a716-446655440004"
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "incomplete.txt",
		TotalSize:    3072,
		ChunkSize:    1024,
		TotalChunks:  3,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	// Create only 2 out of 3 chunks
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)

	for i := 0; i < 2; i++ {
		chunkPath := filepath.Join(partialDir, fmt.Sprintf("chunk_%d", i))
		chunkData := bytes.Repeat([]byte("A"), 1024)
		os.WriteFile(chunkPath, chunkData, 0644)
	}
	// Chunk 2 is missing

	handler := UploadCompleteHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request with missing chunks
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var response models.UploadCompleteErrorResponse
	json.NewDecoder(rr.Body).Decode(&response)

	if len(response.MissingChunks) != 1 {
		t.Errorf("missing_chunks length = %d, want 1", len(response.MissingChunks))
	}

	if response.MissingChunks[0] != 2 {
		t.Errorf("missing chunk = %d, want 2", response.MissingChunks[0])
	}
}

func TestUploadCompleteHandler_UploadNotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadCompleteHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/550e8400-e29b-41d4-a716-446655440000", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 404 Not Found
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestUploadCompleteHandler_InvalidUploadID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadCompleteHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/invalid-id", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUploadStatusHandler_InProgress(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload
	uploadID := "550e8400-e29b-41d4-a716-446655440005"
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "inprogress.txt",
		TotalSize:    3072,
		ChunkSize:    1024,
		TotalChunks:  3,
		Completed:    false,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	// Create 1 out of 3 chunks
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)
	chunkPath := filepath.Join(partialDir, "chunk_0")
	os.WriteFile(chunkPath, bytes.Repeat([]byte("A"), 1024), 0644)

	handler := UploadStatusHandler(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/upload/status/"+uploadID, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response models.UploadStatusResponse
	json.NewDecoder(rr.Body).Decode(&response)

	if response.ChunksReceived != 1 {
		t.Errorf("chunks_received = %d, want 1", response.ChunksReceived)
	}

	if response.TotalChunks != 3 {
		t.Errorf("total_chunks = %d, want 3", response.TotalChunks)
	}

	if len(response.MissingChunks) != 2 {
		t.Errorf("missing_chunks length = %d, want 2", len(response.MissingChunks))
	}

	if response.Complete {
		t.Error("complete should be false")
	}
}

func TestUploadStatusHandler_Completed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize completed upload
	uploadID := "550e8400-e29b-41d4-a716-446655440006"
	claimCode := "testclaimcode123"
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "completed.txt",
		TotalSize:    2048,
		ChunkSize:    1024,
		TotalChunks:  2,
		Completed:    true,
		Status:       "completed",
		ClaimCode:    &claimCode,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	handler := UploadStatusHandler(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/upload/status/"+uploadID, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response models.UploadStatusResponse
	json.NewDecoder(rr.Body).Decode(&response)

	if !response.Complete {
		t.Error("complete should be true")
	}

	if response.ClaimCode == nil {
		t.Error("claim_code should not be nil")
	}

	if *response.ClaimCode != claimCode {
		t.Errorf("claim_code = %s, want %s", *response.ClaimCode, claimCode)
	}

	// Note: download_url is only set when status == "completed"
	// CreatePartialUpload() doesn't save the status field, so it defaults to "uploading"
	// Thus, download_url will be nil even though Completed=true
	// This is expected behavior - download_url is set by the completion handler, not manually
}

func TestUploadStatusHandler_NotFound(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadStatusHandler(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/upload/status/550e8400-e29b-41d4-a716-446655440000", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 404 Not Found
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestUploadStatusHandler_InvalidUploadID(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadStatusHandler(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/upload/status/invalid-id", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUploadChunkHandler_AlreadyCompleted(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Create completed upload
	uploadID := "550e8400-e29b-41d4-a716-446655440007"
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "done.txt",
		TotalSize:    1024,
		ChunkSize:    1024,
		TotalChunks:  1,
		Completed:    true,
		Status:       "completed",
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	handler := UploadChunkHandler(db, cfg)

	// Try to upload chunk to completed upload
	chunkData := bytes.Repeat([]byte("A"), 1024)
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("chunk", "chunk0")
	part.Write(chunkData)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/"+uploadID+"/0", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 409 Conflict
	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestUploadInitHandler_ExpirationValidation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	cfg.SetMaxExpirationHours(168) // 1 week max

	handler := UploadInitHandler(db, cfg)

	// Try to set expiration beyond max
	initReq := models.UploadInitRequest{
		Filename:       "test.txt",
		TotalSize:      1024,
		ExpiresInHours: 720, // 30 days (exceeds max)
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if errorCode, ok := response["code"].(string); !ok || errorCode != "EXPIRATION_TOO_LONG" {
		t.Errorf("code = %v, want EXPIRATION_TOO_LONG", response["code"])
	}
}

func TestUploadInitHandler_DefaultExpiration(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	cfg.SetDefaultExpirationHours(48)

	handler := UploadInitHandler(db, cfg)

	// Negative value should use default
	initReq := models.UploadInitRequest{
		Filename:       "test.txt",
		TotalSize:      1024,
		ExpiresInHours: -1, // Negative = use default
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var response models.UploadInitResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify default expiration was used
	partialUpload, _ := database.GetPartialUpload(db, response.UploadID)
	if partialUpload.ExpiresInHours != 48 {
		t.Errorf("expires_in_hours = %d, want 48 (default)", partialUpload.ExpiresInHours)
	}
}

func TestUploadInitHandler_NeverExpire(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadInitHandler(db, cfg)

	// ExpiresInHours: 0 means "never expire"
	initReq := models.UploadInitRequest{
		Filename:       "test.txt",
		TotalSize:      1024,
		ExpiresInHours: 0, // Never expire
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var response models.UploadInitResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify never-expire was set
	partialUpload, _ := database.GetPartialUpload(db, response.UploadID)
	if partialUpload.ExpiresInHours != 0 {
		t.Errorf("expires_in_hours = %d, want 0 (never expire)", partialUpload.ExpiresInHours)
	}
}

func TestUploadChunkHandler_LastChunkValidation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload: 2500 bytes total, 1024 byte chunks = 3 chunks (1024, 1024, 452)
	uploadID := "550e8400-e29b-41d4-a716-446655440008"
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "test.txt",
		TotalSize:    2500,
		ChunkSize:    1024,
		TotalChunks:  3,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	handler := UploadChunkHandler(db, cfg)

	// Upload last chunk (should be 452 bytes)
	lastChunkSize := 2500 - (2 * 1024) // 452 bytes
	chunkData := bytes.Repeat([]byte("A"), lastChunkSize)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("chunk", "chunk2")
	part.Write(chunkData)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/"+uploadID+"/2", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestUploadCompleteHandler_ChunkIntegrityFailure(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload
	uploadID := "550e8400-e29b-41d4-a716-446655440009"
	partialUpload := &models.PartialUpload{
		UploadID:       uploadID,
		Filename:       "integrity_test.txt",
		TotalSize:      2048,
		ChunkSize:      1024,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   0,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	// Create chunks with WRONG sizes (integrity check should fail)
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)

	// Chunk 0: correct size (1024 bytes)
	chunk0Path := filepath.Join(partialDir, "chunk_0")
	os.WriteFile(chunk0Path, bytes.Repeat([]byte("A"), 1024), 0644)

	// Chunk 1: WRONG size (512 bytes instead of 1024) - integrity check should fail
	chunk1Path := filepath.Join(partialDir, "chunk_1")
	os.WriteFile(chunk1Path, bytes.Repeat([]byte("B"), 512), 0644)

	handler := UploadCompleteHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 400 Bad Request due to integrity failure
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d\nBody: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestUploadCompleteHandler_WithEncryption(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Enable encryption (64 hex characters = 32 bytes for AES-256)
	cfg.EncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// Initialize upload
	uploadID := "550e8400-e29b-41d4-a716-446655440010"
	partialUpload := &models.PartialUpload{
		UploadID:       uploadID,
		Filename:       "encrypted_chunked.txt",
		TotalSize:      2048,
		ChunkSize:      1024,
		TotalChunks:    2,
		ExpiresInHours: 24,
		MaxDownloads:   0,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	// Create all chunks
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)

	for i := 0; i < 2; i++ {
		chunkPath := filepath.Join(partialDir, fmt.Sprintf("chunk_%d", i))
		chunkData := bytes.Repeat([]byte("A"), 1024)
		os.WriteFile(chunkPath, chunkData, 0644)
	}

	handler := UploadCompleteHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 202 Accepted (async assembly)
	if rr.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}

	// Wait for async assembly to complete
	time.Sleep(500 * time.Millisecond)

	// Check that file was created and encrypted
	partialUpload, _ = database.GetPartialUpload(db, uploadID)
	if partialUpload.Status != "completed" {
		t.Errorf("status = %s, want completed", partialUpload.Status)
	}

	// Verify encrypted file exists on disk
	if partialUpload.ClaimCode != nil {
		file, _ := database.GetFileByClaimCode(db, *partialUpload.ClaimCode)
		if file != nil {
			storedPath := filepath.Join(cfg.UploadDir, file.StoredFilename)
			encryptedData, err := os.ReadFile(storedPath)
			if err != nil {
				t.Fatalf("failed to read stored file: %v", err)
			}

			// File should be encrypted (should NOT contain plaintext)
			if bytes.Contains(encryptedData, []byte("AAAA")) {
				t.Error("file appears to be stored in plaintext, not encrypted")
			}
		}
	}
}

func TestUploadCompleteHandler_Expired(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	cfg.PartialUploadExpiryHours = 1 // 1 hour expiry

	// Initialize upload with old last_activity (expired)
	uploadID := "550e8400-e29b-41d4-a716-446655440011"
	partialUpload := &models.PartialUpload{
		UploadID:       uploadID,
		Filename:       "expired.txt",
		TotalSize:      1024,
		ChunkSize:      1024,
		TotalChunks:    1,
		ExpiresInHours: 24,
		CreatedAt:      time.Now().Add(-25 * time.Hour), // Created 25 hours ago
		LastActivity:   time.Now().Add(-25 * time.Hour), // Last activity 25 hours ago (expired!)
	}
	database.CreatePartialUpload(db, partialUpload)

	// Create chunk
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)
	chunkPath := filepath.Join(partialDir, "chunk_0")
	os.WriteFile(chunkPath, bytes.Repeat([]byte("A"), 1024), 0644)

	handler := UploadCompleteHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 410 Gone (expired)
	if rr.Code != http.StatusGone {
		t.Errorf("status = %d, want %d (Gone)", rr.Code, http.StatusGone)
	}
}

func TestUploadCompleteHandler_AlreadyProcessing(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload
	uploadID := "550e8400-e29b-41d4-a716-446655440012"
	partialUpload := &models.PartialUpload{
		UploadID:       uploadID,
		Filename:       "processing.txt",
		TotalSize:      1024,
		ChunkSize:      1024,
		TotalChunks:    1,
		ExpiresInHours: 24,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	// Update status to "processing" (Status field not saved by CreatePartialUpload)
	database.UpdatePartialUploadStatus(db, uploadID, "processing", nil)

	// Create chunk
	partialDir := filepath.Join(cfg.UploadDir, ".partial", uploadID)
	os.MkdirAll(partialDir, 0755)
	chunkPath := filepath.Join(partialDir, "chunk_0")
	os.WriteFile(chunkPath, bytes.Repeat([]byte("A"), 1024), 0644)

	handler := UploadCompleteHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/complete/"+uploadID, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 202 Accepted with processing status (idempotent)
	if rr.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if status, ok := response["status"].(string); !ok || status != "processing" {
		t.Errorf("status = %v, want processing", response["status"])
	}
}

func TestUploadInitHandler_WithUserContext(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Create test user
	testUser := &models.User{
		ID:       456,
		Username: "chunkuser",
		Email:    "chunk@example.com",
		Role:     "user",
	}

	handler := UploadInitHandler(db, cfg)

	initReq := models.UploadInitRequest{
		Filename:       "user_chunked.txt",
		TotalSize:      1024 * 1024,
		ExpiresInHours: 48,
		MaxDownloads:   10,
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Add user to context
	ctx := context.WithValue(req.Context(), middleware.ContextKeyUser, testUser)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusCreated)
	}

	var response models.UploadInitResponse
	json.NewDecoder(rr.Body).Decode(&response)

	// Verify user_id was set in partial upload
	partialUpload, _ := database.GetPartialUpload(db, response.UploadID)
	if partialUpload.UserID == nil {
		t.Fatal("user_id should be set for authenticated upload")
	}

	if *partialUpload.UserID != testUser.ID {
		t.Errorf("user_id = %d, want %d", *partialUpload.UserID, testUser.ID)
	}
}

func TestUploadInitHandler_QuotaExceeded(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Set quota to 1GB (SetQuotaLimitGB takes int64, whole GB only)
	cfg.SetQuotaLimitGB(1) // 1 GB

	// Increase max file size to allow 200MB uploads
	cfg.SetMaxFileSize(300 * 1024 * 1024) // 300MB

	// Create actual file in upload directory (900MB)
	existingFileData := bytes.Repeat([]byte("Y"), 900*1024*1024)
	existingStoredFilename := "existing-chunked-quota-test.dat"
	existingFilePath := filepath.Join(cfg.UploadDir, existingStoredFilename)
	if err := os.WriteFile(existingFilePath, existingFileData, 0644); err != nil {
		t.Fatalf("failed to create existing file: %v", err)
	}

	// Upload a file that uses most of the quota (900MB)
	existingFile := &models.File{
		ClaimCode:        "chunkedquota1",
		OriginalFilename: "existing.dat",
		StoredFilename:   existingStoredFilename,
		FileSize:         900 * 1024 * 1024,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	database.CreateFile(db, existingFile)

	handler := UploadInitHandler(db, cfg)

	// Try to initialize upload for 200MB file (would exceed quota)
	initReq := models.UploadInitRequest{
		Filename:  "new.dat",
		TotalSize: 200 * 1024 * 1024,
	}
	body, _ := json.Marshal(initReq)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should return 507 Insufficient Storage
	if rr.Code != http.StatusInsufficientStorage {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusInsufficientStorage)
	}
}

// Method validation tests

func TestUploadInitHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadInitHandler(db, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/upload/init", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestUploadChunkHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadChunkHandler(db, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/upload/chunk/550e8400-e29b-41d4-a716-446655440000/0", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestUploadCompleteHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadCompleteHandler(db, cfg)

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/upload/complete/550e8400-e29b-41d4-a716-446655440000", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestUploadStatusHandler_MethodNotAllowed(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadStatusHandler(db, cfg)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/upload/status/550e8400-e29b-41d4-a716-446655440000", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestUploadInitHandler_InvalidJSON(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	handler := UploadInitHandler(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestUploadChunkHandler_MissingChunkFile(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload
	uploadID := "550e8400-e29b-41d4-a716-446655440013"
	partialUpload := &models.PartialUpload{
		UploadID:     uploadID,
		Filename:     "test.txt",
		TotalSize:    1024,
		ChunkSize:    1024,
		TotalChunks:  1,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	database.CreatePartialUpload(db, partialUpload)

	handler := UploadChunkHandler(db, cfg)

	// Send request without chunk file in multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/"+uploadID+"/0", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}
