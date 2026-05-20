// Package s3 implements encrypted storage for S3 using SFSE streaming
// encryption. Unlike v1.5.0 of this file, the v1.6.0 implementation streams
// throughout — Retrieve / StreamRange / Store / AssembleChunks never buffer
// a full plaintext or full ciphertext into the heap. See SH-2.2.
//
// New uploads emit SFSE2 with per-chunk AAD (ADR-011). The SFSE2 enc_file_id
// and plaintext length are stashed in S3 object UserMetadata so the wrapper
// is self-contained: no DB plumbing is needed for the wrapper itself to
// decrypt files it wrote. Legacy SFSE1 objects (written by the pre-SH-2.2
// implementation, or files migrated in from another store) are still
// readable via version dispatch.
package s3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/fjmerc/safeshare/internal/storage"
	"github.com/fjmerc/safeshare/internal/utils"
)

const (
	// StreamEncryptionMagic is re-exported here for tests/back-compat callers
	// that imported the s3 package's constant. The on-wire magic is identical
	// across SFSE1 and SFSE2 — the version byte at offset 5 is the format
	// discriminator. Internally this package uses utils.StreamEncryptionMagic.
	StreamEncryptionMagic = utils.StreamEncryptionMagic
	// StreamEncryptionVersion is the SFSE1 version byte. Retained for
	// back-compat with the v1.5.0 test surface.
	StreamEncryptionVersion = utils.StreamEncryptionVersion
	// DefaultEncryptionChunkSize is the same as utils.DefaultChunkSize (10 MB).
	// Kept for back-compat with callers that imported this name.
	DefaultEncryptionChunkSize = utils.DefaultChunkSize

	// S3 UserMetadata keys used by the SFSE2 read path. S3 lowercases keys,
	// strips the x-amz-meta- prefix on read, and limits the combined size of
	// keys + values to 2 KB — well within budget for these three entries.
	s3MetaSFSEVersion       = "safeshare-sfse-version"
	s3MetaSFSE2EncFileID    = "safeshare-sfse2-enc-file-id"
	s3MetaSFSE2PlaintextLen = "safeshare-sfse2-plaintext-len"
)

// S3EncryptedStorage wraps S3Storage and provides transparent SFSE2
// encryption/decryption with streaming throughout.
type S3EncryptedStorage struct {
	backend *S3Storage
	keyHex  string
}

// NewS3EncryptedStorage creates a new S3EncryptedStorage wrapping the given
// S3 backend. keyHex must be a 64-character hexadecimal string (32 bytes for
// AES-256).
func NewS3EncryptedStorage(backend *S3Storage, keyHex string) (*S3EncryptedStorage, error) {
	if keyHex == "" {
		return nil, fmt.Errorf("encryption key is required")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}
	return &S3EncryptedStorage{
		backend: backend,
		keyHex:  keyHex,
	}, nil
}

// Store stream-encrypts the source reader into SFSE2 and uploads the result
// to S3 via multipart manager.Uploader. The plaintext SHA-256 is computed
// alongside the upload (TeeReader on the plaintext side) and returned to the
// caller — production handlers persist it in files.checksum_sha256.
//
// The generated SFSE2 enc_file_id is stashed in S3 UserMetadata so Retrieve
// / StreamRange can recover it without DB context. The plaintext length is
// also stashed (used by SFSE2 to set the is_last AAD bit and validate the
// header trailer on read).
//
// `size` is the exact plaintext length (required by SFSE2's header). For
// streaming sources where the length is unknown a-priori, callers must
// buffer or pre-stat — passing the wrong value will fail decrypt later.
func (es *S3EncryptedStorage) Store(ctx context.Context, filename string, reader io.Reader, size int64) (string, string, error) {
	if size < 0 {
		return "", "", storage.NewStorageErrorWithMessage("Store", filename, nil,
			fmt.Sprintf("size must be non-negative, got %d", size))
	}

	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		return "", "", storage.NewStorageError("Store", filename, err)
	}

	hasher := sha256.New()
	hashedSrc := io.TeeReader(reader, hasher)

	pr, pw := io.Pipe()
	encErrCh := make(chan error, 1)
	go func() {
		// EncryptFileStreamingV2FromReader writes the SFSE2 stream (header +
		// chunks) to pw. When it returns, we must close pw so the uploader
		// sees EOF; on error we propagate via CloseWithError so the uploader
		// fails fast rather than uploading a truncated object.
		encErr := utils.EncryptFileStreamingV2FromReader(pw, hashedSrc, es.keyHex, encFileID, size)
		if encErr != nil {
			_ = pw.CloseWithError(encErr)
		} else {
			_ = pw.Close()
		}
		encErrCh <- encErr
	}()

	_, uploadErr := es.backend.uploader.Upload(ctx, &s3.PutObjectInput{ //nolint:staticcheck // deprecated, migrate to transfermanager in follow-up
		Bucket: aws.String(es.backend.bucket),
		Key:    aws.String(filename),
		Body:   pr,
		Metadata: map[string]string{
			s3MetaSFSEVersion:       "2",
			s3MetaSFSE2EncFileID:    hex.EncodeToString(encFileID),
			s3MetaSFSE2PlaintextLen: strconv.FormatInt(size, 10),
		},
	})
	// Always unblock the encrypt goroutine. If Upload returned without
	// draining pr (early failure / cancellation / SDK quirk on the deprecated
	// path), pw.Write inside EncryptFileStreamingV2FromReader would block
	// forever and the <-encErrCh receive below would deadlock. CloseWithError
	// causes the next pw.Write to return uploadErr; the goroutine returns and
	// sends on encErrCh.
	_ = pr.CloseWithError(uploadErr)
	encErr := <-encErrCh

	// If the encryptor errored, that's the primary failure to report — the
	// uploader's error in that case is almost always "broken pipe" caused by
	// our CloseWithError, which isn't actionable.
	if encErr != nil {
		return "", "", storage.NewStorageError("Store", filename, encErr)
	}
	if uploadErr != nil {
		return "", "", storage.NewStorageError("Store", filename, uploadErr)
	}

	plaintextHash := hex.EncodeToString(hasher.Sum(nil))
	slog.Debug("encrypted file stored in S3",
		"filename", filename,
		"plaintext_size", size,
		"sha256", plaintextHash[:16]+"...",
	)
	return filename, plaintextHash, nil
}

// Retrieve returns an io.ReadCloser that streams the decrypted plaintext of
// filename from S3. The returned reader streams chunk-by-chunk; closing it
// closes the underlying S3 body. SFSE1 (legacy) and SFSE2 are both supported
// via the in-band version byte.
//
// For SFSE2 objects, the per-chunk AAD is verified against the enc_file_id
// loaded from S3 UserMetadata, and the plaintext-length trailer is verified
// after the final chunk. Plaintext SHA-256 is NOT verified at the wrapper
// layer (it requires DB context); production callers that need defense-in-
// depth past AAD should use DecryptFileStreamingAny with a path-based
// source, or call the SH-2.3+ V2-aware wrapper method (not yet implemented).
func (es *S3EncryptedStorage) Retrieve(ctx context.Context, filename string) (io.ReadCloser, error) {
	result, err := es.backend.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(es.backend.bucket),
		Key:    aws.String(filename),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, storage.NewStorageErrorWithMessage("Retrieve", filename, err, "file not found")
		}
		return nil, storage.NewStorageError("Retrieve", filename, err)
	}

	encFileID, _, hasV2Meta := parseSFSE2Metadata(result.Metadata)

	// io.Pipe lets us return an io.ReadCloser without buffering the whole
	// plaintext: a goroutine streams S3 body through the SFSE decryptor,
	// writing decrypted bytes to pw; the caller reads from pr.
	// ContentLength gives us the encrypted-object size, which the V2 reader
	// cross-checks against the header trailer. Catches blunt truncation
	// faster than waiting for the AAD failure on the final chunk.
	var encryptedSize int64 = -1
	if result.ContentLength != nil {
		encryptedSize = *result.ContentLength
	}

	pr, pw := io.Pipe()
	go func() {
		defer result.Body.Close() //nolint:errcheck // best-effort cleanup on the S3 body; the reader's error is already what the caller surfaces
		// Recover from a panic in the decrypt path so the reader-side caller
		// is unblocked with a clear error instead of waiting forever on pr.
		// pw.CloseWithError on the deferred panic path supersedes the normal
		// pw.Close() at the bottom of this function.
		var dErr error
		defer func() {
			if r := recover(); r != nil {
				_ = pw.CloseWithError(fmt.Errorf("retrieve decrypt panic: %v", r))
				panic(r) // re-panic so crash handler / logs still see it
			}
			if dErr != nil {
				_ = pw.CloseWithError(storage.NewStorageError("Retrieve", filename, dErr))
				return
			}
			_ = pw.Close()
		}()

		// V2 reads require an enc_file_id. If metadata is missing it (e.g.
		// the object was written before SH-2.2, or by a different tool), we
		// fall back to passing zeros; that will fail AAD validation on a
		// real V2 file, which is the correct failure mode (don't silently
		// decrypt with a wrong AAD; surface the metadata absence).
		var dispatchEncFileID []byte
		if hasV2Meta {
			dispatchEncFileID = encFileID
		} else {
			dispatchEncFileID = make([]byte, utils.SFSE2EncFileIDSize)
		}

		// expectedPlaintextLen / expectedSHA256Hex are -1 / "" because the
		// wrapper does not have DB context. AAD + the header trailer length
		// check inside DecryptSFSEFromReader are sufficient defense for the
		// wrapper layer; production callers that read via path will get the
		// additional SHA-256 check.
		_, dErr = utils.DecryptSFSEFromReader(result.Body, pw, es.keyHex, dispatchEncFileID, "", -1, encryptedSize)
	}()
	return pr, nil
}

// StreamRange decrypts and streams a plaintext byte range to w. Two S3
// requests are issued in the SFSE2 case: one ranged GetObject for the
// 18-byte header (to learn chunkSize and total_plaintext_len), and one
// ranged GetObject for the covering ciphertext range. Each chunk is
// decrypted and the windowed plaintext is written to w as it arrives —
// no full-file buffering occurs.
//
// For SFSE1 (legacy) objects, the response is the same shape but the second
// fetch covers the open-ended ciphertext tail (V1 has no length trailer to
// bound it).
//
// Range start/end are inclusive plaintext-byte offsets. Returns the number
// of bytes written to w.
func (es *S3EncryptedStorage) StreamRange(ctx context.Context, filename string, start, end int64, w io.Writer) (int64, error) {
	if start < 0 || end < start {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil,
			fmt.Sprintf("invalid range: start=%d, end=%d", start, end))
	}

	// Fetch the 18-byte header (covers V1's 10 bytes too, with 8 trailing
	// ciphertext bytes that we either discard or re-prepend for V1).
	hdrResp, err := es.backend.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(es.backend.bucket),
		Key:    aws.String(filename),
		Range:  aws.String(fmt.Sprintf("bytes=0-%d", utils.SFSE2HeaderSize-1)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, err, "file not found")
		}
		return 0, storage.NewStorageError("StreamRange", filename, err)
	}
	hdrBytes, hdrErr := io.ReadAll(io.LimitReader(hdrResp.Body, int64(utils.SFSE2HeaderSize)))
	_ = hdrResp.Body.Close()
	if hdrErr != nil {
		return 0, storage.NewStorageError("StreamRange", filename, hdrErr)
	}
	if len(hdrBytes) < utils.SFSE1HeaderSize {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil, "object too small to be SFSE")
	}
	if string(hdrBytes[:5]) != utils.StreamEncryptionMagic {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil, "invalid SFSE magic")
	}

	switch hdrBytes[5] {
	case utils.StreamEncryptionVersion:
		// V1: chunk_size at bytes 6-9; no plaintext-length trailer. Use a
		// best-effort fetch from startChunk to end-of-object (S3 returns
		// what it has).
		return es.streamRangeV1(ctx, filename, hdrBytes, start, end, w)
	case utils.StreamEncryptionVersionV2:
		if len(hdrBytes) < utils.SFSE2HeaderSize {
			return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil, "object too small to be SFSE2")
		}
		return es.streamRangeV2(ctx, filename, hdrResp.Metadata, hdrBytes, start, end, w)
	default:
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil,
			fmt.Sprintf("unsupported SFSE version: %d", hdrBytes[5]))
	}
}

// streamRangeV1 handles a plaintext Range request for a legacy SFSE1 object.
// Computes the ciphertext range from V1 chunk math (no totalPlaintextLen
// trailer to bound it), issues a ranged GetObject, and runs the V1 chunk
// decrypt on the body.
func (es *S3EncryptedStorage) streamRangeV1(ctx context.Context, filename string, hdrBytes []byte, start, end int64, w io.Writer) (int64, error) {
	chunkSize := int64(uint32(hdrBytes[6]) | uint32(hdrBytes[7])<<8 | uint32(hdrBytes[8])<<16 | uint32(hdrBytes[9])<<24)
	if chunkSize <= 0 {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil, "invalid SFSE1 chunk_size")
	}
	encChunkSize := chunkSize + int64(utils.SFSE2OverheadPerChunk)
	startChunk := start / chunkSize
	endChunk := end / chunkSize
	ctStart := int64(utils.SFSE1HeaderSize) + startChunk*encChunkSize
	ctEnd := int64(utils.SFSE1HeaderSize) + (endChunk+1)*encChunkSize - 1

	body, err := es.fetchRange(ctx, filename, ctStart, ctEnd)
	if err != nil {
		return 0, err
	}
	defer body.Close() //nolint:errcheck // best-effort close of S3 response body
	return utils.DecryptSFSE1RangeFromReader(body, w, es.keyHex, chunkSize, start, end)
}

// streamRangeV2 handles a plaintext Range request for an SFSE2 object.
// Validates UserMetadata, computes the ciphertext range via
// ComputeSFSE2CiphertextRange, issues a ranged GetObject, and runs the V2
// chunk decrypt on the body.
func (es *S3EncryptedStorage) streamRangeV2(ctx context.Context, filename string, meta map[string]string, hdrBytes []byte, start, end int64, w io.Writer) (int64, error) {
	encFileID, plaintextLen, ok := parseSFSE2Metadata(meta)
	if !ok {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil,
			"SFSE2 object missing required UserMetadata (enc-file-id / plaintext-len)")
	}
	// Cross-check the metadata's plaintext_len against the header's trailer.
	// The header is authenticated by per-chunk AAD on every chunk, so a
	// drift between metadata and header indicates tampering at the metadata
	// layer (which is unsigned).
	hdrPlaintextLen := int64(
		uint64(hdrBytes[10])<<56 | uint64(hdrBytes[11])<<48 | uint64(hdrBytes[12])<<40 | uint64(hdrBytes[13])<<32 |
			uint64(hdrBytes[14])<<24 | uint64(hdrBytes[15])<<16 | uint64(hdrBytes[16])<<8 | uint64(hdrBytes[17]))
	if hdrPlaintextLen != plaintextLen {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil,
			fmt.Sprintf("SFSE2 metadata/header plaintext_len mismatch: meta=%d header=%d", plaintextLen, hdrPlaintextLen))
	}
	chunkSize := int64(uint32(hdrBytes[6]) | uint32(hdrBytes[7])<<8 | uint32(hdrBytes[8])<<16 | uint32(hdrBytes[9])<<24)
	if chunkSize <= 0 {
		return 0, storage.NewStorageErrorWithMessage("StreamRange", filename, nil, "invalid SFSE2 chunk_size")
	}

	ctStart, ctEnd, err := utils.ComputeSFSE2CiphertextRange(start, end, chunkSize, plaintextLen)
	if err != nil {
		return 0, storage.NewStorageError("StreamRange", filename, err)
	}
	if ctEnd < ctStart {
		// Empty plaintext file: nothing to fetch. Caller's request would be
		// rejected by ComputeSFSE2CiphertextRange in normal cases; if we
		// reach here it's a zero-byte object with no chunks to read.
		return 0, nil
	}

	body, err := es.fetchRange(ctx, filename, ctStart, ctEnd)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	return utils.DecryptSFSE2RangeFromReader(body, w, es.keyHex, encFileID, "", chunkSize, plaintextLen, start, end)
}

// fetchRange issues a ranged GetObject and returns the response body. Caller
// is responsible for closing the returned ReadCloser.
func (es *S3EncryptedStorage) fetchRange(ctx context.Context, filename string, ctStart, ctEnd int64) (io.ReadCloser, error) {
	resp, err := es.backend.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(es.backend.bucket),
		Key:    aws.String(filename),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", ctStart, ctEnd)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, storage.NewStorageErrorWithMessage("StreamRange", filename, err, "file not found")
		}
		return nil, storage.NewStorageError("StreamRange", filename, err)
	}
	return resp.Body, nil
}

// Delete passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) Delete(ctx context.Context, filename string) error {
	return es.backend.Delete(ctx, filename)
}

// Exists passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) Exists(ctx context.Context, filename string) (bool, error) {
	return es.backend.Exists(ctx, filename)
}

// GetSize returns the encrypted ciphertext size from S3. Callers that need
// the plaintext size should consult files.file_size in the DB (the wrapper
// also stashes it in S3 UserMetadata, but reading it requires HeadObject —
// callers that already have the row should not pay that round-trip).
func (es *S3EncryptedStorage) GetSize(ctx context.Context, filename string) (int64, error) {
	return es.backend.GetSize(ctx, filename)
}

// SaveChunk passes through to the underlying S3 backend. Chunks are stored
// unencrypted; encryption happens during AssembleChunks.
func (es *S3EncryptedStorage) SaveChunk(ctx context.Context, uploadID string, chunkNum int, data io.Reader, size int64) error {
	return es.backend.SaveChunk(ctx, uploadID, chunkNum, data, size)
}

// GetChunk passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetChunk(ctx context.Context, uploadID string, chunkNum int) (io.ReadCloser, error) {
	return es.backend.GetChunk(ctx, uploadID, chunkNum)
}

// DeleteChunks passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) DeleteChunks(ctx context.Context, uploadID string) error {
	return es.backend.DeleteChunks(ctx, uploadID)
}

// ChunkExists passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) ChunkExists(ctx context.Context, uploadID string, chunkNum int) (bool, int64, error) {
	return es.backend.ChunkExists(ctx, uploadID, chunkNum)
}

// AssembleChunks stream-encrypts the plaintext concatenation of all upload
// chunks into a single SFSE2 object. The plaintext flows through:
//
//	(per-chunk GetObject) → io.MultiReader → TeeReader(SHA-256)
//	  → io.Pipe(writer) → EncryptFileStreamingV2FromReader goroutine
//	      → io.Pipe(reader) → manager.Uploader.Upload
//
// No full plaintext or ciphertext buffer ever exists; each chunk's
// io.ReadCloser is consumed in order and closed before the next is opened.
//
// The total plaintext length (required for SFSE2's header) is computed via
// a single ListObjectsV2 over the partial prefix, summing chunk sizes.
//
// Returns the SHA-256 hash of the assembled plaintext.
func (es *S3EncryptedStorage) AssembleChunks(ctx context.Context, uploadID string, totalChunks int, destFilename string) (string, error) {
	totalPlaintextLen, err := es.sumChunkSizes(ctx, uploadID, totalChunks)
	if err != nil {
		return "", storage.NewStorageError("AssembleChunks", uploadID, err)
	}

	encFileID, err := utils.GenerateEncFileID()
	if err != nil {
		return "", storage.NewStorageError("AssembleChunks", uploadID, err)
	}

	hasher := sha256.New()
	chunkReader := &orderedChunkReader{
		ctx:         ctx,
		backend:     es.backend,
		uploadID:    uploadID,
		totalChunks: totalChunks,
	}
	defer func() { _ = chunkReader.Close() }() // best-effort close of in-flight chunk reader if AssembleChunks errors mid-stream
	hashedSrc := io.TeeReader(chunkReader, hasher)

	pr, pw := io.Pipe()
	encErrCh := make(chan error, 1)
	go func() {
		encErr := utils.EncryptFileStreamingV2FromReader(pw, hashedSrc, es.keyHex, encFileID, totalPlaintextLen)
		if encErr != nil {
			_ = pw.CloseWithError(encErr)
		} else {
			_ = pw.Close()
		}
		encErrCh <- encErr
	}()

	_, uploadErr := es.backend.uploader.Upload(ctx, &s3.PutObjectInput{ //nolint:staticcheck // deprecated, migrate to transfermanager in follow-up
		Bucket: aws.String(es.backend.bucket),
		Key:    aws.String(destFilename),
		Body:   pr,
		Metadata: map[string]string{
			s3MetaSFSEVersion:       "2",
			s3MetaSFSE2EncFileID:    hex.EncodeToString(encFileID),
			s3MetaSFSE2PlaintextLen: strconv.FormatInt(totalPlaintextLen, 10),
		},
	})
	// See Store(): force-close pr to unblock the encrypt goroutine in case
	// the uploader returned without draining (early failure, cancellation,
	// or SDK behavior on the deprecated path).
	_ = pr.CloseWithError(uploadErr)
	encErr := <-encErrCh
	if encErr != nil {
		return "", storage.NewStorageError("AssembleChunks", destFilename, encErr)
	}
	if uploadErr != nil {
		return "", storage.NewStorageError("AssembleChunks", destFilename, uploadErr)
	}

	hashHex := hex.EncodeToString(hasher.Sum(nil))
	slog.Debug("assembled file encrypted in S3",
		"dest_filename", destFilename,
		"plaintext_size", totalPlaintextLen,
		"sha256", hashHex[:16]+"...",
	)
	return hashHex, nil
}

// sumChunkSizes returns the sum of all expected chunk sizes for uploadID.
// Validates that every expected key (chunk_0 … chunk_{totalChunks-1}) is
// present and that no foreign objects exist under the prefix — a stray
// object would otherwise either silently inflate the SFSE2 plaintext_len
// header (corrupt object) or be ignored by orderedChunkReader (also
// corrupt).
//
// Uses ListObjectsV2 (single API call for typical chunk counts) and walks
// the listing into a map keyed by chunk number for O(1) presence check.
func (es *S3EncryptedStorage) sumChunkSizes(ctx context.Context, uploadID string, totalChunks int) (int64, error) {
	prefix := fmt.Sprintf("%s%s/", partialPrefix, uploadID)
	paginator := s3.NewListObjectsV2Paginator(es.backend.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(es.backend.bucket),
		Prefix: aws.String(prefix),
	})

	sizes := make(map[int]int64, totalChunks)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			var chunkNum int
			// getChunkKey emits "<prefix><uploadID>/chunk_<N>"; parse N from
			// the listed key. Unparseable keys are foreign objects under the
			// prefix (e.g., leftover metadata sidecars) and are an error —
			// reject the upload rather than risk a wrong plaintext_len.
			if _, err := fmt.Sscanf(*obj.Key, prefix+"chunk_%d", &chunkNum); err != nil {
				return 0, fmt.Errorf("unexpected object %q under chunk prefix %q", *obj.Key, prefix)
			}
			if chunkNum < 0 || chunkNum >= totalChunks {
				return 0, fmt.Errorf("chunk %d out of expected range [0, %d) under prefix %q", chunkNum, totalChunks, prefix)
			}
			if _, dup := sizes[chunkNum]; dup {
				return 0, fmt.Errorf("duplicate chunk %d under prefix %q", chunkNum, prefix)
			}
			var size int64
			if obj.Size != nil {
				size = *obj.Size
			}
			sizes[chunkNum] = size
		}
	}
	if len(sizes) != totalChunks {
		return 0, fmt.Errorf("expected %d chunks under prefix %q, found %d", totalChunks, prefix, len(sizes))
	}
	var totalSize int64
	for i := 0; i < totalChunks; i++ {
		totalSize += sizes[i]
	}
	return totalSize, nil
}

// orderedChunkReader implements io.Reader by reading chunks 0..totalChunks-1
// sequentially from the backend's chunk storage. The chunk currently being
// read is kept open until exhausted; the next chunk is fetched on demand
// when the current one returns io.EOF.
//
// This is the streaming source for AssembleChunks's encrypt pipeline — at
// most one chunk's worth of S3 body bytes exists at a time, never the full
// upload.
type orderedChunkReader struct {
	ctx         context.Context
	backend     *S3Storage
	uploadID    string
	totalChunks int
	current     io.ReadCloser
	nextIdx     int
}

func (r *orderedChunkReader) Read(p []byte) (int, error) {
	for {
		if r.current == nil {
			if r.nextIdx >= r.totalChunks {
				return 0, io.EOF
			}
			rc, err := r.backend.GetChunk(r.ctx, r.uploadID, r.nextIdx)
			if err != nil {
				return 0, fmt.Errorf("orderedChunkReader: GetChunk(%d): %w", r.nextIdx, err)
			}
			r.current = rc
			r.nextIdx++
		}
		n, err := r.current.Read(p)
		if n > 0 {
			// Returning here with err != nil is fine — caller will see the
			// partial read; next Read() call will trigger the EOF rotation
			// below.
			return n, nil
		}
		if err == io.EOF {
			_ = r.current.Close()
			r.current = nil
			continue
		}
		if err != nil {
			// Close the partially-read body before bubbling up so the SDK
			// can return the HTTP/2 stream to the pool instead of waiting
			// for GC finalization.
			_ = r.current.Close()
			idx := r.nextIdx - 1
			r.current = nil
			return 0, fmt.Errorf("orderedChunkReader: Read chunk %d: %w", idx, err)
		}
		// n==0 && err==nil: spin again. Should not happen for well-behaved
		// readers but defensive against pathological backends.
	}
}

// Close releases the currently-open chunk, if any. Idempotent.
func (r *orderedChunkReader) Close() error {
	if r.current != nil {
		err := r.current.Close()
		r.current = nil
		return err
	}
	return nil
}

// GetMissingChunks passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetMissingChunks(ctx context.Context, uploadID string, totalChunks int) ([]int, error) {
	return es.backend.GetMissingChunks(ctx, uploadID, totalChunks)
}

// GetChunkCount passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetChunkCount(ctx context.Context, uploadID string) (int, error) {
	return es.backend.GetChunkCount(ctx, uploadID)
}

// GetAvailableSpace passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetAvailableSpace(ctx context.Context) (int64, error) {
	return es.backend.GetAvailableSpace(ctx)
}

// GetUsedSpace passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) GetUsedSpace(ctx context.Context) (int64, error) {
	return es.backend.GetUsedSpace(ctx)
}

// HealthCheck passes through to the underlying S3 backend.
func (es *S3EncryptedStorage) HealthCheck(ctx context.Context) error {
	return es.backend.HealthCheck(ctx)
}

// parseSFSE2Metadata extracts the SFSE2 enc_file_id and plaintext length
// from an S3 GetObject's UserMetadata map. AWS SDK v2 returns metadata keys
// already lowercased and with the `x-amz-meta-` prefix stripped, but
// path-style MinIO and other S3-compatible services have been observed to
// return mixed casing; we accept both.
//
// Returns (encFileID, plaintextLen, ok). ok==false means the metadata is
// absent or malformed — caller should treat this as a non-SFSE2 object (or,
// for paths that require SFSE2, error out).
func parseSFSE2Metadata(meta map[string]string) ([]byte, int64, bool) {
	get := func(key string) string {
		if v, ok := meta[key]; ok {
			return v
		}
		// Case-insensitive fallback for non-standard implementations.
		for k, v := range meta {
			if equalFold(k, key) {
				return v
			}
		}
		return ""
	}
	version := get(s3MetaSFSEVersion)
	if version != "2" {
		return nil, 0, false
	}
	idHex := get(s3MetaSFSE2EncFileID)
	if idHex == "" {
		return nil, 0, false
	}
	id, err := hex.DecodeString(idHex)
	if err != nil || len(id) != utils.SFSE2EncFileIDSize {
		return nil, 0, false
	}
	lenStr := get(s3MetaSFSE2PlaintextLen)
	if lenStr == "" {
		return nil, 0, false
	}
	plaintextLen, err := strconv.ParseInt(lenStr, 10, 64)
	if err != nil || plaintextLen < 0 {
		return nil, 0, false
	}
	return id, plaintextLen, true
}

// equalFold compares two ASCII strings case-insensitively. We avoid
// strings.EqualFold because S3 metadata keys are guaranteed ASCII and we
// want to keep this hot path allocation-free.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Verify S3EncryptedStorage implements StorageBackend.
var _ storage.StorageBackend = (*S3EncryptedStorage)(nil)
