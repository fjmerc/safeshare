//go:build integration

// Package s3 integration tests against a live MinIO server.
//
// Required env (set by scripts/test-minio.sh):
//
//	MINIO_HOST           default localhost
//	MINIO_PORT           default 9100
//	MINIO_ACCESS_KEY     default minioadmin
//	MINIO_SECRET_KEY     default minioadmin123
//	MINIO_BUCKET         default safeshare-test
//	SH22_LARGE_FILE_SIZE_GB  override the large-file heap test (default 1, CI: 5)
//
// These tests guard SH-2.2's two acceptance criteria:
//
//  1. Streaming throughout — no io.ReadAll on the source or destination side.
//     Asserted via heap-snapshot diff before/after a large-file round-trip.
//  2. Range correctness — chunk-straddling Range fetches return byte-exact
//     plaintext under concurrency.
//
// Tests are gated by the `integration` build tag so they do not run in the
// default unit-test job. CI invokes them via scripts/test-minio.sh against
// the docker-compose.minio-test.yml MinIO container.
package s3

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/fjmerc/safeshare/internal/utils"
)

const (
	defaultMinioHost      = "localhost"
	defaultMinioPort      = "9100"
	defaultMinioAccessKey = "minioadmin"
	defaultMinioSecretKey = "minioadmin123"
	defaultMinioBucket    = "safeshare-test"
	// testEncryptionKey is fixed across tests so failures can be reproduced
	// outside the test harness. Not a real-world key — never use this value
	// in production.
	testEncryptionKey = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
)

// newTestStorage constructs an S3EncryptedStorage against the MinIO endpoint
// configured by env vars. Skips the test if MinIO is unreachable so a
// developer running `go test -tags=integration` without MinIO running gets a
// clear skip instead of a confusing AWS-SDK retry storm.
func newTestStorage(t *testing.T) *S3EncryptedStorage {
	t.Helper()
	host := envOrDefault("MINIO_HOST", defaultMinioHost)
	port := envOrDefault("MINIO_PORT", defaultMinioPort)
	access := envOrDefault("MINIO_ACCESS_KEY", defaultMinioAccessKey)
	secret := envOrDefault("MINIO_SECRET_KEY", defaultMinioSecretKey)
	bucket := envOrDefault("MINIO_BUCKET", defaultMinioBucket)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	backend, err := NewS3Storage(ctx, S3Config{
		Bucket:          bucket,
		Region:          "us-east-1",
		Endpoint:        fmt.Sprintf("http://%s:%s", host, port),
		AccessKeyID:     access,
		SecretAccessKey: secret,
		PathStyle:       true,
	})
	if err != nil {
		t.Skipf("MinIO unavailable at %s:%s (%v) — start with scripts/test-minio.sh", host, port, err)
	}
	es, err := NewS3EncryptedStorage(backend, testEncryptionKey)
	if err != nil {
		t.Fatalf("NewS3EncryptedStorage: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort prefix wipe so repeat test runs against a persistent
		// MinIO start clean. tmpfs-backed compose volume makes this
		// redundant in CI, but harmless.
		_ = backend.Delete(context.Background(), t.Name())
	})
	return es
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// uniqueKey returns a per-test S3 key. MinIO is shared across tests in this
// file; namespacing by test name + nanosecond timestamp avoids cross-test
// interference if parallelism is later enabled.
func uniqueKey(t *testing.T, suffix string) string {
	t.Helper()
	return fmt.Sprintf("sh22/%s/%d-%s", t.Name(), time.Now().UnixNano(), suffix)
}

// TestRoundTrip_SmallFile exercises the basic Store → Retrieve path with a
// small (< 1 chunk) plaintext. Asserts byte-exact plaintext round-trip and
// returned plaintext SHA-256 matches the source.
func TestRoundTrip_SmallFile(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()

	plaintext := []byte("hello, sfse2 streaming s3 world — small enough to fit in one chunk")
	wantHash := sha256.Sum256(plaintext)
	wantHashHex := hex.EncodeToString(wantHash[:])

	key := uniqueKey(t, "small")
	defer func() { _ = es.Delete(ctx, key) }()

	_, gotHash, err := es.Store(ctx, key, bytes.NewReader(plaintext), int64(len(plaintext)))
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if gotHash != wantHashHex {
		t.Errorf("Store returned hash %s, want %s", gotHash, wantHashHex)
	}

	rc, err := es.Retrieve(ctx, key)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Retrieve read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

// TestRoundTrip_MultiChunk exercises Store → Retrieve across two chunks
// (one full + one short) and verifies StreamRange across a chunk boundary.
func TestRoundTrip_MultiChunk(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()

	// 1.5 chunks of plaintext.
	size := int64(utils.DefaultChunkSize) + int64(utils.DefaultChunkSize)/2
	plaintext := randomBytes(t, size)
	key := uniqueKey(t, "multichunk")
	defer func() { _ = es.Delete(ctx, key) }()

	_, _, err := es.Store(ctx, key, bytes.NewReader(plaintext), size)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Full retrieve.
	rc, err := es.Retrieve(ctx, key)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("Retrieve read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}

	// Range straddling chunk boundary.
	rangeStart := int64(utils.DefaultChunkSize) - 100
	rangeEnd := int64(utils.DefaultChunkSize) + 100
	var buf bytes.Buffer
	n, err := es.StreamRange(ctx, key, rangeStart, rangeEnd, &buf)
	if err != nil {
		t.Fatalf("StreamRange: %v", err)
	}
	want := plaintext[rangeStart : rangeEnd+1]
	if n != int64(len(want)) {
		t.Errorf("StreamRange wrote %d, want %d", n, len(want))
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("StreamRange bytes mismatch")
	}
}

// TestLargeFile_BoundedHeap is the SH-2.2 acceptance test: stream a
// configurably-large file through Store and Retrieve and assert the heap
// never grows close to the file size. Default 1 GB locally; CI runs at 5 GB
// via SH22_LARGE_FILE_SIZE_GB=5.
//
// We assert HeapInuse delta stays under 256 MB — generous enough to absorb
// the SDK's multipart buffers (5 MB part size × small concurrency) and our
// per-chunk decrypt buffer (10 MB), but small enough to fail loudly if any
// path regresses to io.ReadAll.
func TestLargeFile_BoundedHeap(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()

	sizeGB := int64(1)
	if v := os.Getenv("SH22_LARGE_FILE_SIZE_GB"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			sizeGB = parsed
		}
	}
	const gb = int64(1024 * 1024 * 1024)
	totalSize := sizeGB * gb
	t.Logf("large-file test size: %d GB", sizeGB)

	key := uniqueKey(t, "largefile")
	defer func() { _ = es.Delete(ctx, key) }()

	// Generate plaintext on the fly via a deterministic streaming source so
	// we don't materialize totalSize bytes in the test process itself.
	srcSeed := []byte("sh22-large-file-deterministic-stream-marker-2026-05-19")
	src := newDeterministicReader(srcSeed, totalSize)
	hasher := sha256.New()
	teedSrc := io.TeeReader(src, hasher)

	runtime.GC()
	var beforeStats runtime.MemStats
	runtime.ReadMemStats(&beforeStats)

	_, gotHash, err := es.Store(ctx, key, teedSrc, totalSize)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	expectedHash := hex.EncodeToString(hasher.Sum(nil))
	if gotHash != expectedHash {
		t.Fatalf("Store hash mismatch")
	}

	var afterStoreStats runtime.MemStats
	runtime.ReadMemStats(&afterStoreStats)
	storeHeapDelta := int64(afterStoreStats.HeapInuse) - int64(beforeStats.HeapInuse) //nolint:gosec // delta fits int64
	t.Logf("HeapInuse delta after Store: %d bytes (%.1f MB)", storeHeapDelta, float64(storeHeapDelta)/(1024*1024))

	// Retrieve and verify SHA-256 (streaming).
	runtime.GC()
	var beforeRetrieveStats runtime.MemStats
	runtime.ReadMemStats(&beforeRetrieveStats)

	rc, err := es.Retrieve(ctx, key)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	dlHasher := sha256.New()
	written, err := io.Copy(dlHasher, rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("Retrieve stream: %v", err)
	}
	if written != totalSize {
		t.Fatalf("Retrieve wrote %d bytes, want %d", written, totalSize)
	}
	gotPlaintextHash := hex.EncodeToString(dlHasher.Sum(nil))
	if gotPlaintextHash != expectedHash {
		t.Fatalf("Retrieve plaintext SHA-256 mismatch: got %s, want %s", gotPlaintextHash, expectedHash)
	}

	var afterRetrieveStats runtime.MemStats
	runtime.ReadMemStats(&afterRetrieveStats)
	retrieveHeapDelta := int64(afterRetrieveStats.HeapInuse) - int64(beforeRetrieveStats.HeapInuse) //nolint:gosec
	t.Logf("HeapInuse delta after Retrieve: %d bytes (%.1f MB)", retrieveHeapDelta, float64(retrieveHeapDelta)/(1024*1024))

	const maxHeapDelta = int64(256 * 1024 * 1024)
	if storeHeapDelta > maxHeapDelta {
		t.Errorf("Store heap delta %d MB > limit %d MB — likely regression to io.ReadAll on Store",
			storeHeapDelta/(1024*1024), maxHeapDelta/(1024*1024))
	}
	if retrieveHeapDelta > maxHeapDelta {
		t.Errorf("Retrieve heap delta %d MB > limit %d MB — likely regression to io.ReadAll on Retrieve",
			retrieveHeapDelta/(1024*1024), maxHeapDelta/(1024*1024))
	}
}

// TestConcurrentRangeReads runs 10 simultaneous Range downloads of a single
// 100 MB file. Asserts that all goroutines complete successfully and that
// no Range straddling chunks produces corrupted bytes.
func TestConcurrentRangeReads(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()

	const size = int64(100 * 1024 * 1024)
	plaintext := randomBytes(t, size)
	key := uniqueKey(t, "concurrent")
	defer func() { _ = es.Delete(ctx, key) }()

	if _, _, err := es.Store(ctx, key, bytes.NewReader(plaintext), size); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// 10 ranges, each crossing at least one chunk boundary.
	chunkSize := int64(utils.DefaultChunkSize)
	ranges := make([][2]int64, 10)
	for i := range ranges {
		// Anchor each range so it spans chunk i and chunk i+1.
		start := int64(i)*chunkSize + 100
		end := int64(i+1)*chunkSize + 200
		if end >= size {
			end = size - 1
		}
		ranges[i] = [2]int64{start, end}
	}

	var wg sync.WaitGroup
	errs := make([]error, len(ranges))
	for i, r := range ranges {
		wg.Add(1)
		go func(i int, start, end int64) {
			defer wg.Done()
			var buf bytes.Buffer
			n, err := es.StreamRange(ctx, key, start, end, &buf)
			if err != nil {
				errs[i] = fmt.Errorf("range %d-%d: %w", start, end, err)
				return
			}
			want := plaintext[start : end+1]
			if n != int64(len(want)) {
				errs[i] = fmt.Errorf("range %d-%d: wrote %d, want %d", start, end, n, len(want))
				return
			}
			if !bytes.Equal(buf.Bytes(), want) {
				errs[i] = fmt.Errorf("range %d-%d: byte mismatch", start, end)
			}
		}(i, r[0], r[1])
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

// TestEmptyFile validates the zero-byte edge case end-to-end.
func TestEmptyFile(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()
	key := uniqueKey(t, "empty")
	defer func() { _ = es.Delete(ctx, key) }()

	emptyHash := sha256.Sum256(nil)
	emptyHashHex := hex.EncodeToString(emptyHash[:])

	_, gotHash, err := es.Store(ctx, key, bytes.NewReader(nil), 0)
	if err != nil {
		t.Fatalf("Store empty: %v", err)
	}
	if gotHash != emptyHashHex {
		t.Errorf("Store hash %s, want %s", gotHash, emptyHashHex)
	}

	rc, err := es.Retrieve(ctx, key)
	if err != nil {
		t.Fatalf("Retrieve empty: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("Retrieve read: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Retrieve returned %d bytes, want 0", len(got))
	}
}

// TestAssembleChunks_StreamingPipeline writes 3 chunks separately, then
// assembles them through the streaming encrypt → multipart upload pipeline
// and verifies the final object decrypts to the concatenated plaintext.
func TestAssembleChunks_StreamingPipeline(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()

	// Three plaintext chunks (each below the SFSE2 chunk_size of 10 MB so
	// the test is fast, but combined they exceed a single SFSE2 chunk).
	chunks := [][]byte{
		bytes.Repeat([]byte("A"), 3*1024*1024),
		bytes.Repeat([]byte("B"), 4*1024*1024),
		bytes.Repeat([]byte("C"), 5*1024*1024),
	}
	uploadID := fmt.Sprintf("upload-%d", time.Now().UnixNano())
	destKey := uniqueKey(t, "assembled")
	defer func() { _ = es.Delete(ctx, destKey) }()
	defer func() { _ = es.DeleteChunks(ctx, uploadID) }()

	for i, chunk := range chunks {
		if err := es.SaveChunk(ctx, uploadID, i, bytes.NewReader(chunk), int64(len(chunk))); err != nil {
			t.Fatalf("SaveChunk %d: %v", i, err)
		}
	}

	hash, err := es.AssembleChunks(ctx, uploadID, len(chunks), destKey)
	if err != nil {
		t.Fatalf("AssembleChunks: %v", err)
	}
	expected := bytes.Join(chunks, nil)
	expectedHash := sha256.Sum256(expected)
	if hash != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("AssembleChunks hash %s, want %s", hash, hex.EncodeToString(expectedHash[:]))
	}

	rc, err := es.Retrieve(ctx, destKey)
	if err != nil {
		t.Fatalf("Retrieve assembled: %v", err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatalf("Retrieve read: %v", err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("assembled plaintext mismatch: got %d bytes, want %d", len(got), len(expected))
	}
}

// TestTamperedMetadata_FailsCleanly proves that a write-access attacker who
// rewrites the S3 UserMetadata's plaintext_len cannot trick a reader into
// silently truncating: the wrapper's StreamRange cross-checks header vs
// metadata and the V2 chunk decrypt cross-checks against the header trailer
// via per-chunk AAD.
//
// We don't have direct write access to UserMetadata in the AWS SDK without
// rewriting the whole object (no in-place metadata update); we simulate the
// attack by PutObject'ing the original ciphertext with mutated metadata.
func TestTamperedMetadata_FailsCleanly(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()

	plaintext := randomBytes(t, 1024)
	key := uniqueKey(t, "tampered")
	defer func() { _ = es.Delete(ctx, key) }()
	if _, _, err := es.Store(ctx, key, bytes.NewReader(plaintext), int64(len(plaintext))); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Re-download the encrypted ciphertext (raw, not via wrapper).
	rawResp, err := es.backend.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(es.backend.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("raw GetObject: %v", err)
	}
	ciphertext, err := io.ReadAll(rawResp.Body)
	_ = rawResp.Body.Close()
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}

	// Mutate the plaintext_len metadata to claim a smaller (truncated) file.
	mutatedMeta := make(map[string]string, len(rawResp.Metadata))
	for k, v := range rawResp.Metadata {
		mutatedMeta[k] = v
	}
	mutatedMeta[s3MetaSFSE2PlaintextLen] = "10" // claim 10 bytes when actual is 1024

	_, err = es.backend.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(es.backend.bucket),
		Key:      aws.String(key),
		Body:     bytes.NewReader(ciphertext),
		Metadata: mutatedMeta,
	})
	if err != nil {
		t.Fatalf("PutObject with mutated metadata: %v", err)
	}

	// StreamRange must reject the mismatch.
	var buf bytes.Buffer
	_, err = es.StreamRange(ctx, key, 0, 9, &buf)
	if err == nil {
		t.Fatal("expected error from tampered metadata, got nil")
	}
}

// TestTamperedMetadata_StrippedFailsCleanly proves that stripping the SFSE2
// metadata fields entirely results in a clean StreamRange rejection (the
// streamRangeV2 dispatch is selected from the in-band version byte, then
// `parseSFSE2Metadata` returns ok=false because version metadata is absent,
// and the wrapper surfaces "SFSE2 object missing required UserMetadata").
func TestTamperedMetadata_StrippedFailsCleanly(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()

	plaintext := randomBytes(t, 1024)
	key := uniqueKey(t, "stripped")
	defer func() { _ = es.Delete(ctx, key) }()
	if _, _, err := es.Store(ctx, key, bytes.NewReader(plaintext), int64(len(plaintext))); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Re-upload with all SFSE2 metadata stripped.
	rawResp, err := es.backend.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(es.backend.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("raw GetObject: %v", err)
	}
	ciphertext, err := io.ReadAll(rawResp.Body)
	_ = rawResp.Body.Close()
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}
	_, err = es.backend.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(es.backend.bucket),
		Key:      aws.String(key),
		Body:     bytes.NewReader(ciphertext),
		Metadata: map[string]string{}, // no SFSE2 metadata
	})
	if err != nil {
		t.Fatalf("PutObject without metadata: %v", err)
	}

	var buf bytes.Buffer
	_, err = es.StreamRange(ctx, key, 0, 9, &buf)
	if err == nil {
		t.Fatal("expected error from missing metadata, got nil")
	}
}

// TestTamperedMetadata_MutatedEncFileIDFailsCleanly proves that swapping the
// SFSE2 enc_file_id metadata to a different valid hex value causes the per-
// chunk AAD verification to fail — the V2 reader's `gcm.Open` rejects the
// first chunk because the AAD encodes the (wrong) enc_file_id.
func TestTamperedMetadata_MutatedEncFileIDFailsCleanly(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()

	plaintext := randomBytes(t, 1024)
	key := uniqueKey(t, "mutated-encfileid")
	defer func() { _ = es.Delete(ctx, key) }()
	if _, _, err := es.Store(ctx, key, bytes.NewReader(plaintext), int64(len(plaintext))); err != nil {
		t.Fatalf("Store: %v", err)
	}

	rawResp, err := es.backend.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(es.backend.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("raw GetObject: %v", err)
	}
	ciphertext, err := io.ReadAll(rawResp.Body)
	_ = rawResp.Body.Close()
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}

	// Swap enc_file_id to a different valid 32-char hex.
	mutatedMeta := make(map[string]string, len(rawResp.Metadata))
	for k, v := range rawResp.Metadata {
		mutatedMeta[k] = v
	}
	mutatedMeta[s3MetaSFSE2EncFileID] = "ffffffffffffffffffffffffffffffff"

	_, err = es.backend.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(es.backend.bucket),
		Key:      aws.String(key),
		Body:     bytes.NewReader(ciphertext),
		Metadata: mutatedMeta,
	})
	if err != nil {
		t.Fatalf("PutObject with mutated metadata: %v", err)
	}

	var buf bytes.Buffer
	_, err = es.StreamRange(ctx, key, 0, 9, &buf)
	if err == nil {
		t.Fatal("expected error from mutated enc_file_id, got nil")
	}
}

// TestUnknownKey_NotFound asserts the StorageError path for a missing
// object. Caller observes a wrapped err with the "file not found" message.
func TestUnknownKey_NotFound(t *testing.T) {
	es := newTestStorage(t)
	ctx := context.Background()
	_, err := es.Retrieve(ctx, uniqueKey(t, "missing"))
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	var nsk *types.NoSuchKey
	// Either a wrapped NoSuchKey or a StorageError with "file not found";
	// the SDK retry policy may surface either.
	if !errors.As(err, &nsk) && !contains(err.Error(), "not found") {
		t.Errorf("expected not-found error, got %v", err)
	}
}

func contains(haystack, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}

// randomBytes returns n random bytes; helper for tests that need real-ish
// plaintext (defeats compressed-bandwidth optimizations in MinIO).
func randomBytes(t *testing.T, n int64) []byte {
	t.Helper()
	if n > 1<<30 {
		t.Fatalf("randomBytes: %d bytes is too large for in-memory test (use newDeterministicReader instead)", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// deterministicReader produces a streaming bytes source whose contents are
// reproducible from the seed but never materialized in heap. Used by the
// large-file heap test to avoid the test process itself blowing past the
// heap-budget we're trying to assert against the wrapper.
type deterministicReader struct {
	seed   []byte
	pos    int64
	remain int64
}

func newDeterministicReader(seed []byte, size int64) *deterministicReader {
	return &deterministicReader{seed: seed, remain: size}
}

func (d *deterministicReader) Read(p []byte) (int, error) {
	if d.remain == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > d.remain {
		n = int(d.remain)
	}
	for i := 0; i < n; i++ {
		p[i] = d.seed[int((d.pos+int64(i))%int64(len(d.seed)))]
	}
	d.pos += int64(n)
	d.remain -= int64(n)
	return n, nil
}
