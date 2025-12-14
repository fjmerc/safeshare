// Package s3 implements the StorageBackend interface for AWS S3 and S3-compatible storage.
package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/fjmerc/safeshare/internal/storage"
)

const (
	// partialPrefix is the prefix for partial upload chunks in S3
	partialPrefix = ".partial/"

	// maxS3ObjectSize is the maximum object size S3 can store (5 TiB)
	maxS3ObjectSize = 5 * 1024 * 1024 * 1024 * 1024

	// maxChunkNumber is the maximum allowed chunk number (prevents overflow/DoS)
	maxChunkNumber = 100000

	// multipartUploadPartSize is the size for S3 multipart upload parts (5MB minimum)
	multipartUploadPartSize = 5 * 1024 * 1024
)

// S3Config holds configuration for S3 storage.
type S3Config struct {
	Bucket          string
	Region          string
	Endpoint        string // Custom endpoint for MinIO or other S3-compatible services
	AccessKeyID     string
	SecretAccessKey string
	PathStyle       bool  // Use path-style addressing (required for MinIO)
	StorageQuota    int64 // Optional storage quota in bytes (0 = unlimited)
}

// S3Storage implements StorageBackend for AWS S3 and S3-compatible storage.
type S3Storage struct {
	client   *s3.Client
	uploader *manager.Uploader
	bucket   string
	quota    int64 // Storage quota in bytes (0 = unlimited)
}

// NewS3Storage creates a new S3Storage with the given configuration.
func NewS3Storage(ctx context.Context, cfg S3Config) (*S3Storage, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("S3 bucket name is required")
	}

	// Build AWS config options
	var optFuncs []func(*config.LoadOptions) error

	// Set region if specified
	if cfg.Region != "" {
		optFuncs = append(optFuncs, config.WithRegion(cfg.Region))
	}

	// Set custom credentials if provided
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		optFuncs = append(optFuncs, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(ctx, optFuncs...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with optional custom endpoint
	var s3Opts []func(*s3.Options)
	if cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}
	if cfg.PathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Opts...)

	// Create uploader for streaming uploads
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = multipartUploadPartSize
	})

	// Verify bucket access with a HEAD request
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(cfg.Bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access S3 bucket %q: %w", cfg.Bucket, err)
	}

	slog.Info("S3 storage initialized",
		"bucket", cfg.Bucket,
		"region", cfg.Region,
		"endpoint", cfg.Endpoint,
		"path_style", cfg.PathStyle,
	)

	return &S3Storage{
		client:   client,
		uploader: uploader,
		bucket:   cfg.Bucket,
		quota:    cfg.StorageQuota,
	}, nil
}

// validateKey ensures the S3 key doesn't contain path traversal attacks or dangerous characters.
func (s *S3Storage) validateKey(key string) error {
	// Reject empty keys
	if key == "" {
		return fmt.Errorf("empty key not allowed")
	}

	// Reject null bytes which can cause truncation issues
	if strings.ContainsRune(key, '\x00') {
		return fmt.Errorf("null bytes not allowed in key")
	}

	// Reject keys that look URL-encoded to prevent double-encoding attacks
	if strings.Contains(key, "%") {
		return fmt.Errorf("encoded characters not allowed in key")
	}

	// Reject path traversal patterns in the original key BEFORE cleaning
	// This catches "../", "/..", "..", etc. regardless of position
	if strings.Contains(key, "..") {
		return fmt.Errorf("path traversal not allowed: %s", key)
	}

	// Clean the path and check for special values
	cleaned := path.Clean(key)
	if cleaned == "." || cleaned == "/" {
		return fmt.Errorf("invalid key: %s", key)
	}

	return nil
}

// validateUploadID ensures the upload ID is valid and doesn't contain path traversal.
func (s *S3Storage) validateUploadID(uploadID string) error {
	if uploadID == "" {
		return fmt.Errorf("upload ID is required")
	}
	if strings.Contains(uploadID, "..") || strings.Contains(uploadID, "/") {
		return fmt.Errorf("invalid upload ID")
	}
	// Reject null bytes
	if strings.ContainsRune(uploadID, '\x00') {
		return fmt.Errorf("null bytes not allowed in upload ID")
	}
	return nil
}

// validateChunkNum ensures the chunk number is valid.
func (s *S3Storage) validateChunkNum(chunkNum int) error {
	if chunkNum < 0 {
		return fmt.Errorf("chunk number must be non-negative: %d", chunkNum)
	}
	if chunkNum >= maxChunkNumber {
		return fmt.Errorf("chunk number exceeds maximum: %d >= %d", chunkNum, maxChunkNumber)
	}
	return nil
}

// hashingReader wraps a reader to compute SHA256 hash while reading
type hashingReader struct {
	reader io.Reader
	hasher hash.Hash
}

func newHashingReader(r io.Reader) *hashingReader {
	h := sha256.New()
	return &hashingReader{
		reader: io.TeeReader(r, h),
		hasher: h,
	}
}

func (hr *hashingReader) Read(p []byte) (n int, err error) {
	return hr.reader.Read(p)
}

func (hr *hashingReader) Hash() string {
	return hex.EncodeToString(hr.hasher.Sum(nil))
}

// Store writes data from the reader to S3 with the given filename.
// Uses streaming multipart upload to avoid loading entire file into memory.
// Returns the storage path and SHA256 hash of the stored content.
func (s *S3Storage) Store(ctx context.Context, filename string, reader io.Reader, size int64) (string, string, error) {
	if err := s.validateKey(filename); err != nil {
		return "", "", storage.NewStorageErrorWithMessage("Store", filename, err, "key validation failed")
	}

	// Create hashing reader to compute SHA256 while streaming
	hr := newHashingReader(reader)

	// Use multipart upload manager for streaming upload (no memory exhaustion)
	_, err := s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(filename),
		Body:   hr,
	})
	if err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	hash := hr.Hash()

	slog.Debug("file stored in S3",
		"filename", filename,
		"size", size,
		"hash", hash[:16]+"...",
	)

	return filename, hash, nil
}

// Retrieve returns a reader for the stored file from S3.
func (s *S3Storage) Retrieve(ctx context.Context, filename string) (io.ReadCloser, error) {
	if err := s.validateKey(filename); err != nil {
		return nil, storage.NewStorageErrorWithMessage("Retrieve", filename, err, "key validation failed")
	}

	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(filename),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, storage.NewStorageErrorWithMessage("Retrieve", filename, err, "file not found")
		}
		return nil, storage.NewStorageError("Retrieve", filename, err)
	}

	return result.Body, nil
}

// Delete removes a file from S3.
func (s *S3Storage) Delete(ctx context.Context, filename string) error {
	if err := s.validateKey(filename); err != nil {
		return storage.NewStorageErrorWithMessage("Delete", filename, err, "key validation failed")
	}

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(filename),
	})
	if err != nil {
		// S3 doesn't error on delete of non-existent objects by default
		return storage.NewStorageError("Delete", filename, err)
	}

	slog.Debug("file deleted from S3", "filename", filename)
	return nil
}

// Exists checks if a file exists in S3.
func (s *S3Storage) Exists(ctx context.Context, filename string) (bool, error) {
	if err := s.validateKey(filename); err != nil {
		return false, storage.NewStorageErrorWithMessage("Exists", filename, err, "key validation failed")
	}

	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(filename),
	})
	if err != nil {
		var nsk *types.NotFound
		if errors.As(err, &nsk) {
			return false, nil
		}
		// Also check for NoSuchKey error
		var noKey *types.NoSuchKey
		if errors.As(err, &noKey) {
			return false, nil
		}
		return false, storage.NewStorageError("Exists", filename, err)
	}

	return true, nil
}

// GetSize returns the size of a stored file in bytes.
func (s *S3Storage) GetSize(ctx context.Context, filename string) (int64, error) {
	if err := s.validateKey(filename); err != nil {
		return 0, storage.NewStorageErrorWithMessage("GetSize", filename, err, "key validation failed")
	}

	result, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(filename),
	})
	if err != nil {
		var nsk *types.NotFound
		if errors.As(err, &nsk) {
			return 0, storage.NewStorageErrorWithMessage("GetSize", filename, err, "file not found")
		}
		return 0, storage.NewStorageError("GetSize", filename, err)
	}

	if result.ContentLength != nil {
		return *result.ContentLength, nil
	}
	return 0, nil
}

// StreamRange writes a byte range from a stored file to the writer.
func (s *S3Storage) StreamRange(ctx context.Context, filename string, start, end int64, w io.Writer) (int64, error) {
	if start < 0 || end < start {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil,
			fmt.Sprintf("invalid range: start=%d, end=%d", start, end))
	}

	if err := s.validateKey(filename); err != nil {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, err, "key validation failed")
	}

	// S3 Range header is bytes=start-end (both inclusive)
	rangeHeader := fmt.Sprintf("bytes=%d-%d", start, end)

	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(filename),
		Range:  aws.String(rangeHeader),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, err, "file not found")
		}
		return 0, storage.NewStorageError("StreamRange", filename, err)
	}
	defer result.Body.Close()

	written, err := io.Copy(w, result.Body)
	if err != nil {
		return written, storage.NewStorageError("StreamRange", filename, err)
	}

	return written, nil
}

// getChunkKey returns the S3 key for a specific chunk.
func (s *S3Storage) getChunkKey(uploadID string, chunkNum int) string {
	return fmt.Sprintf("%s%s/chunk_%d", partialPrefix, uploadID, chunkNum)
}

// SaveChunk saves a chunk of data for a partial upload.
func (s *S3Storage) SaveChunk(ctx context.Context, uploadID string, chunkNum int, data io.Reader, size int64) error {
	if err := s.validateUploadID(uploadID); err != nil {
		return storage.NewStorageErrorWithMessage("SaveChunk", uploadID, err, "invalid upload ID")
	}
	if err := s.validateChunkNum(chunkNum); err != nil {
		return storage.NewStorageErrorWithMessage("SaveChunk", uploadID, err, "invalid chunk number")
	}

	chunkKey := s.getChunkKey(uploadID, chunkNum)

	// Read chunk data (chunks are bounded by chunk size, so this is safe)
	chunkData, err := io.ReadAll(data)
	if err != nil {
		return storage.NewStorageError("SaveChunk", chunkKey, err)
	}

	// Validate size if provided
	if size > 0 && int64(len(chunkData)) != size {
		return storage.NewStorageErrorWithMessage("SaveChunk", chunkKey, nil,
			fmt.Sprintf("size mismatch: expected %d bytes, got %d bytes", size, len(chunkData)))
	}

	// Upload chunk to S3
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(chunkKey),
		Body:          bytes.NewReader(chunkData),
		ContentLength: aws.Int64(int64(len(chunkData))),
	})
	if err != nil {
		return storage.NewStorageError("SaveChunk", chunkKey, err)
	}

	slog.Debug("chunk saved to S3",
		"upload_id", uploadID,
		"chunk_number", chunkNum,
		"size", len(chunkData),
	)

	return nil
}

// GetChunk returns a reader for a specific chunk.
func (s *S3Storage) GetChunk(ctx context.Context, uploadID string, chunkNum int) (io.ReadCloser, error) {
	if err := s.validateUploadID(uploadID); err != nil {
		return nil, storage.NewStorageErrorWithMessage("GetChunk", uploadID, err, "invalid upload ID")
	}
	if err := s.validateChunkNum(chunkNum); err != nil {
		return nil, storage.NewStorageErrorWithMessage("GetChunk", uploadID, err, "invalid chunk number")
	}

	chunkKey := s.getChunkKey(uploadID, chunkNum)

	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(chunkKey),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, storage.NewStorageErrorWithMessage("GetChunk", chunkKey, err, "chunk not found")
		}
		return nil, storage.NewStorageError("GetChunk", chunkKey, err)
	}

	return result.Body, nil
}

// DeleteChunks removes all chunks for an upload session.
func (s *S3Storage) DeleteChunks(ctx context.Context, uploadID string) error {
	if err := s.validateUploadID(uploadID); err != nil {
		return storage.NewStorageErrorWithMessage("DeleteChunks", uploadID, err, "invalid upload ID")
	}

	prefix := fmt.Sprintf("%s%s/", partialPrefix, uploadID)

	// List all chunks for this upload
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})

	var objectsToDelete []types.ObjectIdentifier
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return storage.NewStorageError("DeleteChunks", uploadID, err)
		}

		for _, obj := range page.Contents {
			objectsToDelete = append(objectsToDelete, types.ObjectIdentifier{
				Key: obj.Key,
			})
		}
	}

	if len(objectsToDelete) == 0 {
		return nil // No chunks to delete
	}

	// Delete all objects in a single batch request (max 1000 per request)
	for i := 0; i < len(objectsToDelete); i += 1000 {
		end := i + 1000
		if end > len(objectsToDelete) {
			end = len(objectsToDelete)
		}

		_, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(s.bucket),
			Delete: &types.Delete{
				Objects: objectsToDelete[i:end],
				Quiet:   aws.Bool(true),
			},
		})
		if err != nil {
			return storage.NewStorageError("DeleteChunks", uploadID, err)
		}
	}

	slog.Debug("chunks deleted from S3", "upload_id", uploadID, "count", len(objectsToDelete))
	return nil
}

// ChunkExists checks if a specific chunk exists and returns its size.
func (s *S3Storage) ChunkExists(ctx context.Context, uploadID string, chunkNum int) (bool, int64, error) {
	if err := s.validateUploadID(uploadID); err != nil {
		return false, 0, storage.NewStorageErrorWithMessage("ChunkExists", uploadID, err, "invalid upload ID")
	}
	if err := s.validateChunkNum(chunkNum); err != nil {
		return false, 0, storage.NewStorageErrorWithMessage("ChunkExists", uploadID, err, "invalid chunk number")
	}

	chunkKey := s.getChunkKey(uploadID, chunkNum)

	result, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(chunkKey),
	})
	if err != nil {
		var nsk *types.NotFound
		if errors.As(err, &nsk) {
			return false, 0, nil
		}
		var noKey *types.NoSuchKey
		if errors.As(err, &noKey) {
			return false, 0, nil
		}
		return false, 0, storage.NewStorageError("ChunkExists", chunkKey, err)
	}

	size := int64(0)
	if result.ContentLength != nil {
		size = *result.ContentLength
	}

	return true, size, nil
}

// AssembleChunks combines all chunks into a single file using S3 multipart upload.
// This avoids loading all chunks into memory at once.
// Returns the SHA256 hash of the assembled file.
func (s *S3Storage) AssembleChunks(ctx context.Context, uploadID string, totalChunks int, destFilename string) (string, error) {
	if err := s.validateUploadID(uploadID); err != nil {
		return "", storage.NewStorageErrorWithMessage("AssembleChunks", uploadID, err, "invalid upload ID")
	}
	if err := s.validateKey(destFilename); err != nil {
		return "", storage.NewStorageErrorWithMessage("AssembleChunks", destFilename, err, "key validation failed")
	}
	if totalChunks <= 0 || totalChunks > maxChunkNumber {
		return "", storage.NewStorageErrorWithMessage("AssembleChunks", uploadID, nil,
			fmt.Sprintf("invalid total chunks: %d", totalChunks))
	}

	startTime := time.Now()

	slog.Info("assembling chunks in S3",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"dest_filename", destFilename,
	)

	// Create S3 multipart upload
	createResp, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(destFilename),
	})
	if err != nil {
		return "", storage.NewStorageError("AssembleChunks", destFilename, err)
	}

	uploadID2 := createResp.UploadId
	var completedParts []types.CompletedPart
	hasher := sha256.New()
	var totalBytesRead int64

	// Process chunks one at a time to avoid memory exhaustion
	for i := 0; i < totalChunks; i++ {
		chunkReader, err := s.GetChunk(ctx, uploadID, i)
		if err != nil {
			// Abort multipart upload on failure
			_, _ = s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{ //nolint:errcheck // Best-effort cleanup
				Bucket:   aws.String(s.bucket),
				Key:      aws.String(destFilename),
				UploadId: uploadID2,
			})
			// Check if chunk is missing
			var nsk *types.NoSuchKey
			if errors.As(err, &nsk) {
				return "", storage.NewStorageErrorWithMessage("AssembleChunks", uploadID, nil,
					fmt.Sprintf("chunk %d missing during assembly", i))
			}
			return "", err
		}

		// Read chunk for hashing and upload as part (chunks are bounded)
		chunkData, readErr := io.ReadAll(chunkReader)
		chunkReader.Close()
		if readErr != nil {
			_, _ = s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{ //nolint:errcheck // Best-effort cleanup
				Bucket:   aws.String(s.bucket),
				Key:      aws.String(destFilename),
				UploadId: uploadID2,
			})
			return "", storage.NewStorageError("AssembleChunks", fmt.Sprintf("chunk_%d", i), readErr)
		}

		hasher.Write(chunkData)
		totalBytesRead += int64(len(chunkData))

		// Upload part (S3 part numbers are 1-indexed)
		partResp, err := s.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     aws.String(s.bucket),
			Key:        aws.String(destFilename),
			PartNumber: aws.Int32(int32(i + 1)),
			UploadId:   uploadID2,
			Body:       bytes.NewReader(chunkData),
		})
		if err != nil {
			_, _ = s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{ //nolint:errcheck // Best-effort cleanup
				Bucket:   aws.String(s.bucket),
				Key:      aws.String(destFilename),
				UploadId: uploadID2,
			})
			return "", storage.NewStorageError("AssembleChunks", fmt.Sprintf("chunk_%d", i), err)
		}

		completedParts = append(completedParts, types.CompletedPart{
			ETag:       partResp.ETag,
			PartNumber: aws.Int32(int32(i + 1)),
		})

		// Log progress every 100 chunks
		if (i+1)%100 == 0 || i == totalChunks-1 {
			slog.Debug("chunk assembly progress",
				"upload_id", uploadID,
				"chunks_processed", i+1,
				"total_chunks", totalChunks,
				"bytes_assembled", totalBytesRead,
			)
		}
	}

	// Complete multipart upload
	_, err = s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(destFilename),
		UploadId: uploadID2,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		_, _ = s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{ //nolint:errcheck // Best-effort cleanup
			Bucket:   aws.String(s.bucket),
			Key:      aws.String(destFilename),
			UploadId: uploadID2,
		})
		return "", storage.NewStorageError("AssembleChunks", destFilename, err)
	}

	hash := hex.EncodeToString(hasher.Sum(nil))

	duration := time.Since(startTime)
	throughputMBps := float64(totalBytesRead) / duration.Seconds() / (1024 * 1024)

	slog.Info("chunk assembly complete",
		"upload_id", uploadID,
		"total_chunks", totalChunks,
		"total_bytes", totalBytesRead,
		"duration_ms", duration.Milliseconds(),
		"throughput_mbps", fmt.Sprintf("%.1f", throughputMBps),
		"sha256_hash", hash[:16]+"...",
	)

	return hash, nil
}

// GetMissingChunks returns a sorted list of missing chunk numbers.
func (s *S3Storage) GetMissingChunks(ctx context.Context, uploadID string, totalChunks int) ([]int, error) {
	if err := s.validateUploadID(uploadID); err != nil {
		return nil, storage.NewStorageErrorWithMessage("GetMissingChunks", uploadID, err, "invalid upload ID")
	}
	if totalChunks <= 0 || totalChunks > maxChunkNumber {
		return nil, storage.NewStorageErrorWithMessage("GetMissingChunks", uploadID, nil,
			fmt.Sprintf("invalid total chunks: %d", totalChunks))
	}

	var missing []int

	for i := 0; i < totalChunks; i++ {
		exists, _, err := s.ChunkExists(ctx, uploadID, i)
		if err != nil {
			return nil, err
		}
		if !exists {
			missing = append(missing, i)
		}
	}

	return missing, nil
}

// GetChunkCount returns the number of chunks present for an upload.
func (s *S3Storage) GetChunkCount(ctx context.Context, uploadID string) (int, error) {
	if err := s.validateUploadID(uploadID); err != nil {
		return 0, storage.NewStorageErrorWithMessage("GetChunkCount", uploadID, err, "invalid upload ID")
	}

	prefix := fmt.Sprintf("%s%s/", partialPrefix, uploadID)

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})

	count := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return 0, storage.NewStorageError("GetChunkCount", uploadID, err)
		}
		count += len(page.Contents)
	}

	return count, nil
}

// GetAvailableSpace returns the available storage space in bytes.
// For S3, this returns the configured quota minus used space, or a large default if no quota.
func (s *S3Storage) GetAvailableSpace(ctx context.Context) (int64, error) {
	if s.quota <= 0 {
		// No quota configured, return maximum S3 object size as a practical limit
		return maxS3ObjectSize, nil
	}

	used, err := s.GetUsedSpace(ctx)
	if err != nil {
		return 0, err
	}

	available := s.quota - used
	if available < 0 {
		available = 0
	}

	return available, nil
}

// GetUsedSpace returns the storage space currently used in bytes.
// This lists all objects in the bucket and sums their sizes.
func (s *S3Storage) GetUsedSpace(ctx context.Context) (int64, error) {
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
	})

	var totalSize int64
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return 0, storage.NewStorageError("GetUsedSpace", s.bucket, err)
		}

		for _, obj := range page.Contents {
			if obj.Size != nil {
				totalSize += *obj.Size
			}
		}
	}

	return totalSize, nil
}

// GetChunkNumbers returns a sorted list of chunk numbers that exist for an upload.
func (s *S3Storage) GetChunkNumbers(ctx context.Context, uploadID string) ([]int, error) {
	if err := s.validateUploadID(uploadID); err != nil {
		return nil, storage.NewStorageErrorWithMessage("GetChunkNumbers", uploadID, err, "invalid upload ID")
	}

	prefix := fmt.Sprintf("%s%s/", partialPrefix, uploadID)

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})

	var chunkNumbers []int
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, storage.NewStorageError("GetChunkNumbers", uploadID, err)
		}

		for _, obj := range page.Contents {
			if obj.Key != nil {
				// Parse chunk number from key (e.g., ".partial/uploadID/chunk_N")
				key := *obj.Key
				var chunkNum int
				// Extract the filename part after the prefix
				if strings.HasPrefix(key, prefix) {
					remainder := key[len(prefix):]
					if _, err := fmt.Sscanf(remainder, "chunk_%d", &chunkNum); err == nil {
						chunkNumbers = append(chunkNumbers, chunkNum)
					}
				}
			}
		}
	}

	sort.Ints(chunkNumbers)
	return chunkNumbers, nil
}

// HealthCheck performs a health check on the S3 storage backend.
// It verifies that the bucket is accessible by performing a HEAD request.
// Includes a 5-second timeout to prevent indefinite blocking on network issues.
func (s *S3Storage) HealthCheck(ctx context.Context) error {
	// Add reasonable timeout for health checks if context doesn't have one
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.client.HeadBucket(checkCtx, &s3.HeadBucketInput{
		Bucket: aws.String(s.bucket),
	})
	if err != nil {
		return storage.NewStorageErrorWithMessage("HealthCheck", s.bucket, err, "S3 bucket not accessible")
	}
	return nil
}
