// Package mock provides a mock implementation of the storage.StorageBackend interface for testing.
// This allows tests to run without filesystem operations and provides configurable behavior.
package mock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/fjmerc/safeshare/internal/storage"
)

// StorageBackend is a mock implementation of storage.StorageBackend for testing.
// It stores all data in memory and provides configurable behavior for tests.
type StorageBackend struct {
	mu sync.RWMutex

	// Storage
	files  map[string][]byte              // filename -> content
	chunks map[string]map[int][]byte      // uploadID -> chunkNum -> content

	// Space tracking
	availableSpace int64
	usedSpace      int64

	// Error injection for testing
	StoreError           error
	RetrieveError        error
	DeleteError          error
	ExistsError          error
	GetSizeError         error
	StreamRangeError     error
	SaveChunkError       error
	GetChunkError        error
	DeleteChunksError    error
	ChunkExistsError     error
	AssembleChunksError  error
	GetMissingChunksError error
	GetChunkCountError    error
	GetAvailableSpaceError error
	GetUsedSpaceError     error

	// Custom behavior hooks
	OnStore          func(ctx context.Context, filename string, reader io.Reader, size int64) (string, string, error)
	OnRetrieve       func(ctx context.Context, filename string) (io.ReadCloser, error)
	OnDelete         func(ctx context.Context, filename string) error
	OnAssembleChunks func(ctx context.Context, uploadID string, totalChunks int, destFilename string) (string, error)
}

// NewStorageBackend creates a new mock StorageBackend with default behavior.
func NewStorageBackend() *StorageBackend {
	return &StorageBackend{
		files:          make(map[string][]byte),
		chunks:         make(map[string]map[int][]byte),
		availableSpace: 100 * 1024 * 1024 * 1024, // 100GB default
		usedSpace:      0,
	}
}

// Ensure StorageBackend implements storage.StorageBackend
var _ storage.StorageBackend = (*StorageBackend)(nil)

// Reset clears all files, chunks, and errors for a fresh test state.
func (s *StorageBackend) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.files = make(map[string][]byte)
	s.chunks = make(map[string]map[int][]byte)
	s.availableSpace = 100 * 1024 * 1024 * 1024
	s.usedSpace = 0

	// Clear all errors
	s.StoreError = nil
	s.RetrieveError = nil
	s.DeleteError = nil
	s.ExistsError = nil
	s.GetSizeError = nil
	s.StreamRangeError = nil
	s.SaveChunkError = nil
	s.GetChunkError = nil
	s.DeleteChunksError = nil
	s.ChunkExistsError = nil
	s.AssembleChunksError = nil
	s.GetMissingChunksError = nil
	s.GetChunkCountError = nil
	s.GetAvailableSpaceError = nil
	s.GetUsedSpaceError = nil

	// Clear hooks
	s.OnStore = nil
	s.OnRetrieve = nil
	s.OnDelete = nil
	s.OnAssembleChunks = nil
}

// SetAvailableSpace sets the available space for testing quota scenarios.
func (s *StorageBackend) SetAvailableSpace(bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.availableSpace = bytes
}

// AddFile directly adds a file to the mock storage for test setup.
func (s *StorageBackend) AddFile(filename string, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.files[filename] = make([]byte, len(content))
	copy(s.files[filename], content)
	s.usedSpace += int64(len(content))
}

// GetFileContent returns the content of a file (for test assertions).
func (s *StorageBackend) GetFileContent(filename string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	content, exists := s.files[filename]
	if !exists {
		return nil, false
	}

	contentCopy := make([]byte, len(content))
	copy(contentCopy, content)
	return contentCopy, true
}

// GetAllFiles returns all filenames in storage (for test assertions).
func (s *StorageBackend) GetAllFiles() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filenames := make([]string, 0, len(s.files))
	for name := range s.files {
		filenames = append(filenames, name)
	}
	return filenames
}

// Store implements storage.StorageBackend.Store
func (s *StorageBackend) Store(ctx context.Context, filename string, reader io.Reader, size int64) (string, string, error) {
	if s.StoreError != nil {
		return "", "", s.StoreError
	}

	if s.OnStore != nil {
		return s.OnStore(ctx, filename, reader, size)
	}

	// Check context
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	default:
	}

	// Read all content
	content, err := io.ReadAll(reader)
	if err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	// Validate size
	if size > 0 && int64(len(content)) != size {
		return "", "", storage.NewStorageErrorWithMessage("Store", filename,
			fmt.Errorf("size mismatch: expected %d, got %d", size, len(content)),
			"file size mismatch")
	}

	// Calculate hash
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check space
	if s.availableSpace > 0 && s.usedSpace+int64(len(content)) > s.availableSpace {
		return "", "", storage.NewStorageErrorWithMessage("Store", filename, nil, "insufficient storage space")
	}

	// Store file
	s.files[filename] = content
	s.usedSpace += int64(len(content))

	return filename, hashStr, nil
}

// Retrieve implements storage.StorageBackend.Retrieve
func (s *StorageBackend) Retrieve(ctx context.Context, filename string) (io.ReadCloser, error) {
	if s.RetrieveError != nil {
		return nil, s.RetrieveError
	}

	if s.OnRetrieve != nil {
		return s.OnRetrieve(ctx, filename)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	content, exists := s.files[filename]
	if !exists {
		return nil, storage.NewStorageErrorWithMessage("Retrieve", filename, nil, "file not found")
	}

	// Return a copy as a ReadCloser
	contentCopy := make([]byte, len(content))
	copy(contentCopy, content)

	return io.NopCloser(bytes.NewReader(contentCopy)), nil
}

// Delete implements storage.StorageBackend.Delete
func (s *StorageBackend) Delete(ctx context.Context, filename string) error {
	if s.DeleteError != nil {
		return s.DeleteError
	}

	if s.OnDelete != nil {
		return s.OnDelete(ctx, filename)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	content, exists := s.files[filename]
	if !exists {
		return storage.NewStorageErrorWithMessage("Delete", filename, nil, "file not found")
	}

	s.usedSpace -= int64(len(content))
	delete(s.files, filename)

	return nil
}

// Exists implements storage.StorageBackend.Exists
func (s *StorageBackend) Exists(ctx context.Context, filename string) (bool, error) {
	if s.ExistsError != nil {
		return false, s.ExistsError
	}

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.files[filename]
	return exists, nil
}

// GetSize implements storage.StorageBackend.GetSize
func (s *StorageBackend) GetSize(ctx context.Context, filename string) (int64, error) {
	if s.GetSizeError != nil {
		return 0, s.GetSizeError
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	content, exists := s.files[filename]
	if !exists {
		return 0, storage.NewStorageErrorWithMessage("GetSize", filename, nil, "file not found")
	}

	return int64(len(content)), nil
}

// StreamRange implements storage.StorageBackend.StreamRange
func (s *StorageBackend) StreamRange(ctx context.Context, filename string, start, end int64, w io.Writer) (int64, error) {
	if s.StreamRangeError != nil {
		return 0, s.StreamRangeError
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	content, exists := s.files[filename]
	if !exists {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil, "file not found")
	}

	fileSize := int64(len(content))

	// Validate range
	if start < 0 || start >= fileSize {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil, "invalid start position")
	}
	if end < start {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil, "invalid range: end < start")
	}
	if end >= fileSize {
		end = fileSize - 1
	}

	// Write the range
	rangeContent := content[start : end+1]
	n, err := w.Write(rangeContent)
	if err != nil {
		return int64(n), storage.NewStorageError("StreamRange", filename, err)
	}

	return int64(n), nil
}

// SaveChunk implements storage.StorageBackend.SaveChunk
func (s *StorageBackend) SaveChunk(ctx context.Context, uploadID string, chunkNum int, data io.Reader, size int64) error {
	if s.SaveChunkError != nil {
		return s.SaveChunkError
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	content, err := io.ReadAll(data)
	if err != nil {
		return storage.NewStorageError("SaveChunk", fmt.Sprintf("%s/chunk_%d", uploadID, chunkNum), err)
	}

	if size > 0 && int64(len(content)) != size {
		return storage.NewStorageErrorWithMessage("SaveChunk", fmt.Sprintf("%s/chunk_%d", uploadID, chunkNum),
			fmt.Errorf("size mismatch: expected %d, got %d", size, len(content)),
			"chunk size mismatch")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.chunks[uploadID] == nil {
		s.chunks[uploadID] = make(map[int][]byte)
	}

	s.chunks[uploadID][chunkNum] = content
	s.usedSpace += int64(len(content))

	return nil
}

// GetChunk implements storage.StorageBackend.GetChunk
func (s *StorageBackend) GetChunk(ctx context.Context, uploadID string, chunkNum int) (io.ReadCloser, error) {
	if s.GetChunkError != nil {
		return nil, s.GetChunkError
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	uploadChunks, exists := s.chunks[uploadID]
	if !exists {
		return nil, storage.NewStorageErrorWithMessage("GetChunk", fmt.Sprintf("%s/chunk_%d", uploadID, chunkNum), nil, "upload not found")
	}

	content, exists := uploadChunks[chunkNum]
	if !exists {
		return nil, storage.NewStorageErrorWithMessage("GetChunk", fmt.Sprintf("%s/chunk_%d", uploadID, chunkNum), nil, "chunk not found")
	}

	contentCopy := make([]byte, len(content))
	copy(contentCopy, content)

	return io.NopCloser(bytes.NewReader(contentCopy)), nil
}

// DeleteChunks implements storage.StorageBackend.DeleteChunks
func (s *StorageBackend) DeleteChunks(ctx context.Context, uploadID string) error {
	if s.DeleteChunksError != nil {
		return s.DeleteChunksError
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	uploadChunks, exists := s.chunks[uploadID]
	if !exists {
		return nil // No error if chunks don't exist
	}

	// Update used space
	for _, content := range uploadChunks {
		s.usedSpace -= int64(len(content))
	}

	delete(s.chunks, uploadID)
	return nil
}

// ChunkExists implements storage.StorageBackend.ChunkExists
func (s *StorageBackend) ChunkExists(ctx context.Context, uploadID string, chunkNum int) (bool, int64, error) {
	if s.ChunkExistsError != nil {
		return false, 0, s.ChunkExistsError
	}

	select {
	case <-ctx.Done():
		return false, 0, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	uploadChunks, exists := s.chunks[uploadID]
	if !exists {
		return false, 0, nil
	}

	content, exists := uploadChunks[chunkNum]
	if !exists {
		return false, 0, nil
	}

	return true, int64(len(content)), nil
}

// AssembleChunks implements storage.StorageBackend.AssembleChunks
func (s *StorageBackend) AssembleChunks(ctx context.Context, uploadID string, totalChunks int, destFilename string) (string, error) {
	if s.AssembleChunksError != nil {
		return "", s.AssembleChunksError
	}

	if s.OnAssembleChunks != nil {
		return s.OnAssembleChunks(ctx, uploadID, totalChunks, destFilename)
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	uploadChunks, exists := s.chunks[uploadID]
	if !exists {
		return "", storage.NewStorageErrorWithMessage("AssembleChunks", uploadID, nil, "upload not found")
	}

	// Check all chunks exist
	for i := 0; i < totalChunks; i++ {
		if _, ok := uploadChunks[i]; !ok {
			return "", storage.NewStorageErrorWithMessage("AssembleChunks", uploadID,
				fmt.Errorf("missing chunk %d", i), "missing chunks")
		}
	}

	// Assemble file
	var assembled bytes.Buffer
	for i := 0; i < totalChunks; i++ {
		assembled.Write(uploadChunks[i])
	}

	content := assembled.Bytes()
	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	// Store assembled file
	s.files[destFilename] = content

	// Clean up chunks (update used space - chunks removed, file added)
	var chunksSize int64
	for _, chunk := range uploadChunks {
		chunksSize += int64(len(chunk))
	}
	s.usedSpace = s.usedSpace - chunksSize + int64(len(content))

	delete(s.chunks, uploadID)

	return hashStr, nil
}

// GetMissingChunks implements storage.StorageBackend.GetMissingChunks
func (s *StorageBackend) GetMissingChunks(ctx context.Context, uploadID string, totalChunks int) ([]int, error) {
	if s.GetMissingChunksError != nil {
		return nil, s.GetMissingChunksError
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	uploadChunks := s.chunks[uploadID]

	var missing []int
	for i := 0; i < totalChunks; i++ {
		if uploadChunks == nil || uploadChunks[i] == nil {
			missing = append(missing, i)
		}
	}

	sort.Ints(missing)
	return missing, nil
}

// GetChunkCount implements storage.StorageBackend.GetChunkCount
func (s *StorageBackend) GetChunkCount(ctx context.Context, uploadID string) (int, error) {
	if s.GetChunkCountError != nil {
		return 0, s.GetChunkCountError
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	uploadChunks, exists := s.chunks[uploadID]
	if !exists {
		return 0, nil
	}

	return len(uploadChunks), nil
}

// GetAvailableSpace implements storage.StorageBackend.GetAvailableSpace
func (s *StorageBackend) GetAvailableSpace(ctx context.Context) (int64, error) {
	if s.GetAvailableSpaceError != nil {
		return 0, s.GetAvailableSpaceError
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.availableSpace - s.usedSpace, nil
}

// GetUsedSpace implements storage.StorageBackend.GetUsedSpace
func (s *StorageBackend) GetUsedSpace(ctx context.Context) (int64, error) {
	if s.GetUsedSpaceError != nil {
		return 0, s.GetUsedSpaceError
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.usedSpace, nil
}

// AddChunk directly adds a chunk for test setup (bypasses SaveChunk logic).
func (s *StorageBackend) AddChunk(uploadID string, chunkNum int, content []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.chunks[uploadID] == nil {
		s.chunks[uploadID] = make(map[int][]byte)
	}

	contentCopy := make([]byte, len(content))
	copy(contentCopy, content)
	s.chunks[uploadID][chunkNum] = contentCopy
	s.usedSpace += int64(len(content))
}

// GetChunkContent returns the content of a chunk for test assertions.
func (s *StorageBackend) GetChunkContent(uploadID string, chunkNum int) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uploadChunks, exists := s.chunks[uploadID]
	if !exists {
		return nil, false
	}

	content, exists := uploadChunks[chunkNum]
	if !exists {
		return nil, false
	}

	contentCopy := make([]byte, len(content))
	copy(contentCopy, content)
	return contentCopy, true
}
