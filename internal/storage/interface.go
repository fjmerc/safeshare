// Package storage provides abstraction for file storage operations.
// This enables future support for different storage backends (local filesystem, S3, etc.)
// without changing the handler code.
package storage

import (
	"context"
	"io"
)

// StorageBackend defines the interface for file storage operations.
// Implementations can support local filesystem, S3, or other storage providers.
type StorageBackend interface {
	// File operations

	// Store writes data from the reader to storage with the given filename.
	// Returns the storage path (may differ from filename) and SHA256 hash of the stored content.
	// The size parameter is used for validation and may be used for pre-allocation.
	Store(ctx context.Context, filename string, reader io.Reader, size int64) (path string, hash string, err error)

	// Retrieve returns a reader for the stored file.
	// The caller is responsible for closing the returned ReadCloser.
	Retrieve(ctx context.Context, filename string) (io.ReadCloser, error)

	// Delete removes a file from storage.
	Delete(ctx context.Context, filename string) error

	// Exists checks if a file exists in storage.
	Exists(ctx context.Context, filename string) (bool, error)

	// GetSize returns the size of a stored file in bytes.
	GetSize(ctx context.Context, filename string) (int64, error)

	// Range operations (for HTTP Range support)

	// StreamRange writes a byte range from a stored file to the writer.
	// start and end are inclusive byte offsets (0-indexed).
	// Returns the number of bytes written.
	StreamRange(ctx context.Context, filename string, start, end int64, w io.Writer) (int64, error)

	// Chunk operations (for resumable uploads)

	// SaveChunk saves a chunk of data for a partial upload.
	// uploadID uniquely identifies the upload session.
	// chunkNum is the 0-indexed chunk number.
	SaveChunk(ctx context.Context, uploadID string, chunkNum int, data io.Reader, size int64) error

	// GetChunk returns a reader for a specific chunk.
	// The caller is responsible for closing the returned ReadCloser.
	GetChunk(ctx context.Context, uploadID string, chunkNum int) (io.ReadCloser, error)

	// DeleteChunks removes all chunks for an upload session.
	DeleteChunks(ctx context.Context, uploadID string) error

	// ChunkExists checks if a specific chunk exists and returns its size.
	ChunkExists(ctx context.Context, uploadID string, chunkNum int) (exists bool, size int64, err error)

	// AssembleChunks combines all chunks into a single file.
	// Returns the SHA256 hash of the assembled file.
	AssembleChunks(ctx context.Context, uploadID string, totalChunks int, destFilename string) (hash string, err error)

	// GetMissingChunks returns a sorted list of missing chunk numbers.
	GetMissingChunks(ctx context.Context, uploadID string, totalChunks int) ([]int, error)

	// GetChunkCount returns the number of chunks present for an upload.
	GetChunkCount(ctx context.Context, uploadID string) (int, error)

	// Space management

	// GetAvailableSpace returns the available storage space in bytes.
	// For local storage, this is disk space. For S3, this may return a configured limit.
	GetAvailableSpace(ctx context.Context) (int64, error)

	// GetUsedSpace returns the storage space currently used in bytes.
	GetUsedSpace(ctx context.Context) (int64, error)
}

// StorageError represents errors from storage operations with additional context.
type StorageError struct {
	Op      string // Operation that failed (e.g., "Store", "Retrieve", "Delete")
	Path    string // Path or filename involved
	Err     error  // Underlying error
	Message string // Human-readable message
}

func (e *StorageError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Path != "" {
		return e.Op + " " + e.Path + ": " + e.Err.Error()
	}
	return e.Op + ": " + e.Err.Error()
}

func (e *StorageError) Unwrap() error {
	return e.Err
}

// NewStorageError creates a new StorageError with the given details.
func NewStorageError(op, path string, err error) *StorageError {
	return &StorageError{
		Op:   op,
		Path: path,
		Err:  err,
	}
}

// NewStorageErrorWithMessage creates a new StorageError with a custom message.
func NewStorageErrorWithMessage(op, path string, err error, message string) *StorageError {
	return &StorageError{
		Op:      op,
		Path:    path,
		Err:     err,
		Message: message,
	}
}
