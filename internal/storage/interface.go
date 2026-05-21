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

	// Health check

	// HealthCheck performs a health check on the storage backend.
	// Returns nil if healthy, or an error describing the issue.
	HealthCheck(ctx context.Context) error
}

// IntegrityVerifyingBackend is implemented by storage backends that can
// authenticate retrieved bytes against DB-sourced expectations
// (`expectedEncFileID` + `expectedSHA256Hex` + `expectedPlaintextLen`).
// This is the substitution-attack defence documented in ADR-013 / SH-3.5:
// an attacker with write access to the underlying storage (e.g. a
// compromised S3 bucket) cannot swap an object body + metadata for
// another same-key file when the caller passes the DB-recorded
// expectations through to decrypt.
//
// `expectedEncFileID` is the headline defence and is enforced PRE-STREAM:
// it is cross-checked against the SFSE2 object's metadata-supplied
// enc_file_id before any chunk is fetched. A mismatch (the body+metadata
// were swapped for another file's) returns an error before any plaintext
// is written to the caller's `io.Writer` / `io.Reader`. When the metadata
// enc_file_id matches the DB value, the same value is then used as
// per-chunk AAD input — so a body-only swap (metadata kept, body
// replaced with another file's ciphertext) fails on the first chunk's
// AAD check, again before any plaintext leaves the wrapper.
//
// `expectedSHA256Hex` and `expectedPlaintextLen` are belt-and-suspenders
// against the (out-of-scope) attacker who also has the encryption key —
// they catch re-encrypted substitutions but only AFTER bytes have been
// streamed (the SHA-256 is a full-file hash; partial-write semantics of
// `io.Pipe` mean these checks fire too late to prevent client receipt).
// Production handlers SHOULD pass all three.
//
// Filesystem backends MAY implement this trivially by delegating to the
// non-verifying Retrieve / StreamRange — their bytes share a trust
// boundary with the DB row, so substitution requires already-root access.
// S3 / object-store backends MUST verify (the storage layer is on a
// separate trust boundary from the DB).
//
// Sentinels:
//   - `expectedEncFileID == nil` skips the pre-stream cross-check
//     (admin recovery tools that genuinely have no DB context).
//   - `expectedSHA256Hex == ""` skips the post-decrypt SHA-256 verify.
//   - `expectedPlaintextLen == -1` skips the length cross-check.
//
// Passing all-sentinel values reduces these methods to their legacy
// equivalents and forfeits the substitution defence.
type IntegrityVerifyingBackend interface {
	// RetrieveWithExpected returns a reader for the decrypted plaintext of
	// `filename`, with substitution detection enforced PRE-STREAM via
	// expectedEncFileID. See type docstring for the sentinel contract.
	//
	// IMPORTANT: when the metadata enc_file_id matches expectedEncFileID
	// but the body has been swapped for another same-key file's ciphertext,
	// the AAD check on chunk 1 fails inside the decrypt goroutine — the
	// returned reader will surface the error on the first Read and ZERO
	// plaintext bytes will have been written. Callers that pipe the reader
	// to an HTTP response MUST observe the Read error and not assume the
	// bytes that did flow are authoritative until io.Copy returns nil.
	RetrieveWithExpected(
		ctx context.Context,
		filename string,
		expectedEncFileID []byte,
		expectedSHA256Hex string,
		expectedPlaintextLen int64,
	) (io.ReadCloser, error)

	// StreamRangeWithExpected writes the byte range [start, end] of the
	// decrypted plaintext to w, with the same DB-sourced expectations
	// honoured. expectedEncFileID is cross-checked synchronously before
	// any chunk is fetched and before any decryption begins; mismatches
	// return an error pre-stream. SHA-256 post-decrypt verify only runs
	// for full-file reads (start == 0 && end == expectedPlaintextLen-1);
	// partial Range reads cannot compute the full-file hash, but the
	// enc_file_id cross-check + AAD verification protect partial reads
	// against substitution regardless. Returns the number of plaintext
	// bytes written.
	StreamRangeWithExpected(
		ctx context.Context,
		filename string,
		start, end int64,
		expectedEncFileID []byte,
		expectedSHA256Hex string,
		expectedPlaintextLen int64,
		w io.Writer,
	) (int64, error)
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
