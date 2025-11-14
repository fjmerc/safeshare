package handlers

import (
	"bytes"
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
		Filename:        "testfile.txt",
		TotalSize:       1024 * 1024, // 1 MB
		ExpiresInHours:  24,
		MaxDownloads:    5,
		Password:        "",
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

	if errorCode, ok := response["error_code"].(string); !ok || errorCode != "BLOCKED_EXTENSION" {
		t.Errorf("error_code = %v, want BLOCKED_EXTENSION", response["error_code"])
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

	// Initialize upload first
	partialUpload := &models.PartialUpload{
		UploadID:    "test-upload-id-12345678",
		Filename:    "test.txt",
		TotalSize:   2048,
		ChunkSize:   1024,
		TotalChunks: 2,
		CreatedAt:   time.Now(),
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

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/test-upload-id-12345678/0", &buf)
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
		UploadID:    "test-upload-id-12345678",
		Filename:    "test.txt",
		TotalSize:   2048,
		ChunkSize:   1024,
		TotalChunks: 2,
		CreatedAt:   time.Now(),
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

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/test-upload-id-12345678/5", &buf)
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
		UploadID:    "test-upload-id-12345678",
		Filename:    "test.txt",
		TotalSize:   2048,
		ChunkSize:   1024,
		TotalChunks: 2,
		CreatedAt:   time.Now(),
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

	req := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/test-upload-id-12345678/0", &buf)
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
		UploadID:    "test-upload-id-12345678",
		Filename:    "test.txt",
		TotalSize:   2048,
		ChunkSize:   1024,
		TotalChunks: 2,
		CreatedAt:   time.Now(),
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

	req1 := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/test-upload-id-12345678/0", &buf1)
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

	req2 := httptest.NewRequest(http.MethodPost, "/api/upload/chunk/test-upload-id-12345678/0", &buf2)
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
	uploadID := "test-complete-12345678"
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

	// Create all chunks on disk
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
	uploadID := "test-missing-12345678"
	partialUpload := &models.PartialUpload{
		UploadID:    uploadID,
		Filename:    "incomplete.txt",
		TotalSize:   3072,
		ChunkSize:   1024,
		TotalChunks: 3,
		CreatedAt:   time.Now(),
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
	uploadID := "test-status-12345678"
	partialUpload := &models.PartialUpload{
		UploadID:    uploadID,
		Filename:    "inprogress.txt",
		TotalSize:   3072,
		ChunkSize:   1024,
		TotalChunks: 3,
		Completed:   false,
		CreatedAt:   time.Now(),
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
	uploadID := "test-completed-12345"
	claimCode := "testclaimcode123"
	partialUpload := &models.PartialUpload{
		UploadID:    uploadID,
		Filename:    "completed.txt",
		TotalSize:   2048,
		ChunkSize:   1024,
		TotalChunks: 2,
		Completed:   true,
		Status:      "completed",
		ClaimCode:   &claimCode,
		CreatedAt:   time.Now(),
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

	if response.DownloadURL == nil {
		t.Error("download_url should not be nil for completed upload")
	}
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
	uploadID := "test-completed-chunk"
	partialUpload := &models.PartialUpload{
		UploadID:    uploadID,
		Filename:    "done.txt",
		TotalSize:   1024,
		ChunkSize:   1024,
		TotalChunks: 1,
		Completed:   true,
		Status:      "completed",
		CreatedAt:   time.Now(),
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

	if errorCode, ok := response["error_code"].(string); !ok || errorCode != "EXPIRATION_TOO_LONG" {
		t.Errorf("error_code = %v, want EXPIRATION_TOO_LONG", response["error_code"])
	}
}

func TestUploadInitHandler_DefaultExpiration(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true
	cfg.SetDefaultExpirationHours(48)

	handler := UploadInitHandler(db, cfg)

	// Don't specify expires_in_hours (should use default)
	initReq := models.UploadInitRequest{
		Filename:       "test.txt",
		TotalSize:      1024,
		ExpiresInHours: 0, // Will use default
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

func TestUploadChunkHandler_LastChunkValidation(t *testing.T) {
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	cfg.ChunkedUploadEnabled = true

	// Initialize upload: 2500 bytes total, 1024 byte chunks = 3 chunks (1024, 1024, 452)
	uploadID := "test-lastchunk-1234"
	partialUpload := &models.PartialUpload{
		UploadID:    uploadID,
		Filename:    "test.txt",
		TotalSize:   2500,
		ChunkSize:   1024,
		TotalChunks: 3,
		CreatedAt:   time.Now(),
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
