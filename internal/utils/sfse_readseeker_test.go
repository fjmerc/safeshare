package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const testSFSEReaderKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
const testSFSEReaderOtherKey = "9999999999999999999999999999999999999999999999999999999999999999"

// --- manual SFSE1/SFSE2 builders (small, caller-chosen chunk sizes) --------
//
// The production encrypt helpers hardcode DefaultChunkSize (10MB), which
// makes chunk-boundary testing prohibitively slow. These builders write the
// same wire format by hand with a small chunkSize so tests can exercise
// multi-chunk / boundary / swap scenarios on tiny inputs.

func buildSFSE1(t *testing.T, plaintext []byte, chunkSize uint32, keyHex string) []byte {
	t.Helper()
	gcm, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		t.Fatalf("newGCMFromKeyHex: %v", err)
	}
	var buf bytes.Buffer
	buf.WriteString(StreamEncryptionMagic)
	buf.WriteByte(StreamEncryptionVersion)
	var cs [4]byte
	binary.LittleEndian.PutUint32(cs[:], chunkSize)
	buf.Write(cs[:])

	for i := 0; i < len(plaintext); i += int(chunkSize) {
		end := i + int(chunkSize)
		if end > len(plaintext) {
			end = len(plaintext)
		}
		nonce := make([]byte, SFSE2NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		buf.Write(gcm.Seal(nonce, nonce, plaintext[i:end], nil))
	}
	return buf.Bytes()
}

func buildSFSE2(t *testing.T, plaintext []byte, chunkSize uint32, keyHex string, encFileID []byte) []byte {
	t.Helper()
	data, err := buildSFSE2Bytes(plaintext, chunkSize, keyHex, encFileID)
	if err != nil {
		t.Fatalf("buildSFSE2Bytes: %v", err)
	}
	return data
}

// buildSFSE2Bytes is the testing.TB-agnostic core of buildSFSE2, usable from
// both tests and benchmarks.
func buildSFSE2Bytes(plaintext []byte, chunkSize uint32, keyHex string, encFileID []byte) ([]byte, error) {
	gcm, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(StreamEncryptionMagic)
	buf.WriteByte(StreamEncryptionVersionV2)
	var cs [4]byte
	binary.LittleEndian.PutUint32(cs[:], chunkSize)
	buf.Write(cs[:])
	var pl [8]byte
	binary.BigEndian.PutUint64(pl[:], uint64(len(plaintext)))
	buf.Write(pl[:])

	totalChunks := chunkCountFromPlaintextLen(int64(len(plaintext)), int64(chunkSize))
	for idx := int64(0); idx < totalChunks; idx++ {
		start := idx * int64(chunkSize)
		end := start + int64(chunkSize)
		if end > int64(len(plaintext)) {
			end = int64(len(plaintext))
		}
		isLast := idx == totalChunks-1
		aad, err := buildSFSE2AAD(encFileID, uint64(idx), isLast)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, SFSE2NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		buf.Write(gcm.Seal(nonce, nonce, plaintext[start:end], aad))
	}
	return buf.Bytes(), nil
}

func writeSFSEFile(t *testing.T, name string, data []byte) (*os.File, os.FileInfo) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	return f, fi
}

func randomPlaintext(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// --- round trip: V1 -----------------------------------------------------

func TestSFSEReader_V1_RoundTripRandomSeekRead(t *testing.T) {
	const chunkSize = 37
	plaintext := randomPlaintext(t, chunkSize*5+13) // several full chunks + a short final one
	data := buildSFSE1(t, plaintext, chunkSize, testSFSEReaderKey)
	f, fi := writeSFSEFile(t, "v1.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, nil, int64(len(plaintext)), "")
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer r.Close()

	assertRandomSeekRead(t, r, plaintext)
}

func TestSFSEReader_V1_ZeroByte(t *testing.T) {
	data := buildSFSE1(t, nil, DefaultChunkSize, testSFSEReaderKey)
	f, fi := writeSFSEFile(t, "v1-empty.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, nil, 0, "")
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer r.Close()

	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("Read() = (%d, %v), want (0, io.EOF)", n, err)
	}
	if size, err := r.Seek(0, io.SeekEnd); err != nil || size != 0 {
		t.Fatalf("Seek(SeekEnd) = (%d, %v), want (0, nil)", size, err)
	}
}

// --- round trip: V2 -----------------------------------------------------

func TestSFSEReader_V2_RoundTripRandomSeekRead(t *testing.T) {
	const chunkSize = 41
	plaintext := randomPlaintext(t, chunkSize*6+7)
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)
	f, fi := writeSFSEFile(t, "v2.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), sha256Hex(plaintext))
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer r.Close()

	assertRandomSeekRead(t, r, plaintext)
}

func TestSFSEReader_V2_ChunkBoundaries(t *testing.T) {
	const chunkSize = 16
	for _, n := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, chunkSize * 3, chunkSize*3 - 1, chunkSize*3 + 1} {
		n := n
		t.Run("n="+strconv.Itoa(n), func(t *testing.T) {
			plaintext := randomPlaintext(t, n)
			encFileID := newTestEncFileID(t)
			data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)
			f, fi := writeSFSEFile(t, "v2-boundary.sfse", data)

			r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(n), sha256Hex(plaintext))
			if err != nil {
				t.Fatalf("OpenSFSEReader: %v", err)
			}
			defer r.Close()

			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
			}
		})
	}
}

func TestSFSEReader_V2_ZeroByte(t *testing.T) {
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, nil, DefaultChunkSize, testSFSEReaderKey, encFileID)
	f, fi := writeSFSEFile(t, "v2-empty.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, 0, sha256Hex(nil))
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer r.Close()

	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("Read() = (%d, %v), want (0, io.EOF)", n, err)
	}
}

// --- Prime / wrong key ----------------------------------------------------

func TestSFSEReader_Prime_WrongKeyErrors(t *testing.T) {
	const chunkSize = 32
	plaintext := randomPlaintext(t, chunkSize*3)
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)
	f, fi := writeSFSEFile(t, "v2-wrongkey.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderOtherKey, encFileID, int64(len(plaintext)), "")
	if err != nil {
		t.Fatalf("OpenSFSEReader (structural validation should not depend on key correctness): %v", err)
	}
	defer r.Close()

	if err := r.Prime(0); err == nil {
		t.Fatalf("Prime() with wrong key: want error, got nil")
	}
	if r.Err() == nil {
		t.Fatalf("Err() after failed Prime: want non-nil")
	}

	if _, err := r.Read(make([]byte, 1)); err == nil {
		t.Fatalf("Read() after failed Prime: want sticky error, got nil")
	}
}

// --- open-time size validation (truncation / appended data) --------------

func TestSFSEReader_Open_RejectsTruncatedFile(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := randomPlaintext(t, 128)
	data := buildSFSE2(t, plaintext, 32, testSFSEReaderKey, encFileID)
	truncated := data[:len(data)-5]
	f, fi := writeSFSEFile(t, "v2-truncated.sfse", truncated)

	_, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), "")
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("OpenSFSEReader on truncated file: err = %v, want ErrSFSE2IntegrityCheckFailed", err)
	}
}

func TestSFSEReader_Open_RejectsAppendedData(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := randomPlaintext(t, 128)
	data := buildSFSE2(t, plaintext, 32, testSFSEReaderKey, encFileID)
	appended := append(append([]byte{}, data...), []byte("trailing garbage")...)
	f, fi := writeSFSEFile(t, "v2-appended.sfse", appended)

	_, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), "")
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("OpenSFSEReader on file with appended data: err = %v, want ErrSFSE2IntegrityCheckFailed", err)
	}
}

// --- swapped chunk fails AEAD (SFSE2 AAD binds chunk_index) ---------------

func TestSFSEReader_V2_SwappedChunkFailsAEAD(t *testing.T) {
	const chunkSize = 20
	plaintext := randomPlaintext(t, chunkSize*4) // 4 full chunks, all same ciphertext size
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)

	encChunkSize := int64(chunkSize) + SFSE2OverheadPerChunk
	c0Start := int64(SFSE2HeaderSize)
	c1Start := c0Start + encChunkSize
	// Swap the first two (same-size, non-final) chunks in place — total
	// file size is unchanged, so the open-time size check still passes.
	tmp := make([]byte, encChunkSize)
	copy(tmp, data[c0Start:c0Start+encChunkSize])
	copy(data[c0Start:c0Start+encChunkSize], data[c1Start:c1Start+encChunkSize])
	copy(data[c1Start:c1Start+encChunkSize], tmp)

	f, fi := writeSFSEFile(t, "v2-swapped.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), "")
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer r.Close()

	if _, err := io.ReadAll(r); err == nil {
		t.Fatalf("ReadAll over swapped chunks: want AEAD failure, got nil error")
	}
}

// --- whole-file hash mismatch withholds the final chunk's bytes ----------

func TestSFSEReader_V2_HashMismatchWithholdsFinalChunk(t *testing.T) {
	const chunkSize = 10
	plaintext := randomPlaintext(t, chunkSize+5) // 2 chunks: one full, one short final
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)
	f, fi := writeSFSEFile(t, "v2-hashmismatch.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), sha256Hex([]byte("wrong content entirely")))
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer r.Close()

	first := make([]byte, chunkSize)
	n, err := io.ReadFull(r, first)
	if err != nil || n != chunkSize {
		t.Fatalf("first chunk read = (%d, %v), want (%d, nil)", n, err, chunkSize)
	}
	if !bytes.Equal(first, plaintext[:chunkSize]) {
		t.Fatalf("first chunk mismatch")
	}

	// The second Read triggers decryption of the final chunk, where the
	// digest is verified before any bytes are handed back.
	rest := make([]byte, 5)
	n, err = r.Read(rest)
	if n != 0 {
		t.Fatalf("final-chunk Read on hash mismatch returned %d bytes, want 0 (withheld)", n)
	}
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("final-chunk Read err = %v, want ErrSFSE2IntegrityCheckFailed", err)
	}
	if !errors.Is(r.Err(), ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("Err() = %v, want ErrSFSE2IntegrityCheckFailed", r.Err())
	}
}

// --- non-contiguous access disables (never falsely fails) hash check -----

func TestSFSEReader_V2_SeekBeforeSequentialReadDisablesHash(t *testing.T) {
	const chunkSize = 10
	plaintext := randomPlaintext(t, chunkSize*3)
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)
	f, fi := writeSFSEFile(t, "v2-seek-first.sfse", data)

	// Intentionally wrong hash — but since the read never starts at offset
	// 0, verification must never engage, so no error should surface.
	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), sha256Hex([]byte("also wrong")))
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer r.Close()

	if _, err := r.Seek(int64(chunkSize*2), io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plaintext[chunkSize*2:]) {
		t.Fatalf("tail read mismatch")
	}
}

// --- pooled buffer reuse ---------------------------------------------------

func TestSFSEReader_PoolReuse_LowAllocations(t *testing.T) {
	const chunkSize = DefaultChunkSize
	plaintext := randomPlaintext(t, 100)
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)
	path := filepath.Join(t.TempDir(), "pooled.sfse")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Warm the pool once before measuring.
	warmupSFSEReaderOpenReadClose(t, path, encFileID, int64(len(plaintext)))

	allocs := testing.AllocsPerRun(20, func() {
		warmupSFSEReaderOpenReadClose(t, path, encFileID, int64(len(plaintext)))
	})
	// A fresh (unpooled) DefaultChunkSize buffer alone is a 10MB+28-byte
	// allocation; with the pool doing its job, a full open/read/close cycle
	// should stay in the tens of allocations, not "one per chunk buffer".
	if allocs > 60 {
		t.Fatalf("AllocsPerRun = %.1f, want <= 60 (pooled buffer should be reused)", allocs)
	}
}

func warmupSFSEReaderOpenReadClose(t *testing.T, path string, encFileID []byte, plainLen int64) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, plainLen, "")
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	r.Close()
}

func BenchmarkSFSEReader_OpenReadClose(b *testing.B) {
	const chunkSize = DefaultChunkSize
	plaintext := make([]byte, 100)
	encFileID := make([]byte, SFSE2EncFileIDSize)
	data, err := buildSFSE2Bytes(plaintext, chunkSize, testSFSEReaderKey, encFileID)
	if err != nil {
		b.Fatalf("buildSFSE2Bytes: %v", err)
	}
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.sfse")
	if err := os.WriteFile(path, data, 0600); err != nil {
		b.Fatalf("WriteFile: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		f, err := os.Open(path)
		if err != nil {
			b.Fatalf("Open: %v", err)
		}
		fi, err := f.Stat()
		if err != nil {
			b.Fatalf("Stat: %v", err)
		}
		r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), "")
		if err != nil {
			b.Fatalf("OpenSFSEReader: %v", err)
		}
		if _, err := io.ReadAll(r); err != nil {
			b.Fatalf("ReadAll: %v", err)
		}
		r.Close()
		f.Close()
	}
}

// --- helpers ----------------------------------------------------------

func assertRandomSeekRead(t *testing.T, r *SFSEReader, plaintext []byte) {
	t.Helper()
	size := int64(len(plaintext))
	for i := 0; i < 200; i++ {
		start := randInt64(t, size+1)
		maxLen := size - start
		length := int64(0)
		if maxLen > 0 {
			length = randInt64(t, maxLen+1)
		}
		if _, err := r.Seek(start, io.SeekStart); err != nil {
			t.Fatalf("Seek(%d): %v", start, err)
		}
		got := make([]byte, length)
		n, err := io.ReadFull(r, got)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			t.Fatalf("Read at %d len %d: %v", start, length, err)
		}
		want := plaintext[start : start+int64(n)]
		if !bytes.Equal(got[:n], want) {
			t.Fatalf("mismatch at start=%d len=%d: got %v want %v", start, length, got[:n], want)
		}
	}
}

func randInt64(t *testing.T, n int64) int64 {
	t.Helper()
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	return v.Int64()
}

// TestSFSEReader_UseAfterClose checks that Close is idempotent and that the
// reader fails cleanly afterwards instead of touching its released buffer.
func TestSFSEReader_UseAfterClose(t *testing.T) {
	const chunkSize = 16
	plaintext := randomPlaintext(t, chunkSize*3)
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)
	f, fi := writeSFSEFile(t, "v2-closed.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), sha256Hex(plaintext))
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := r.Read(buf); err != nil { // loads chunk 0, pos 5
		t.Fatalf("Read: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if _, err := r.Read(buf); !errors.Is(err, errSFSEReaderClosed) {
		t.Errorf("Read after Close (same chunk) = %v, want errSFSEReaderClosed", err)
	}
	if _, err := r.Seek(chunkSize*2, io.SeekStart); !errors.Is(err, errSFSEReaderClosed) {
		t.Errorf("Seek after Close = %v, want errSFSEReaderClosed", err)
	}
	if err := r.Prime(chunkSize * 2); !errors.Is(err, errSFSEReaderClosed) {
		t.Errorf("Prime after Close = %v, want errSFSEReaderClosed", err)
	}
	if r.Err() != nil {
		t.Errorf("Err after a clean Close = %v, want nil", r.Err())
	}
}

// TestSFSEReader_SeekWhence covers io.SeekCurrent, an invalid whence and a
// negative resulting position.
func TestSFSEReader_SeekWhence(t *testing.T) {
	const chunkSize = 16
	plaintext := randomPlaintext(t, chunkSize*2+3)
	encFileID := newTestEncFileID(t)
	data := buildSFSE2(t, plaintext, chunkSize, testSFSEReaderKey, encFileID)
	f, fi := writeSFSEFile(t, "v2-whence.sfse", data)

	r, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, int64(len(plaintext)), sha256Hex(plaintext))
	if err != nil {
		t.Fatalf("OpenSFSEReader: %v", err)
	}
	defer r.Close()

	if pos, err := r.Seek(10, io.SeekStart); err != nil || pos != 10 {
		t.Fatalf("SeekStart = %d, %v", pos, err)
	}
	if pos, err := r.Seek(7, io.SeekCurrent); err != nil || pos != 17 {
		t.Fatalf("SeekCurrent = %d, %v; want 17", pos, err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, plaintext[17:21]) {
		t.Fatalf("read after SeekCurrent = %x, %v; want %x", got, err, plaintext[17:21])
	}
	if _, err := r.Seek(0, 42); err == nil {
		t.Error("invalid whence: want error")
	}
	if _, err := r.Seek(-1, io.SeekStart); err == nil {
		t.Error("negative position: want error")
	}
	if pos, err := r.Seek(-3, io.SeekEnd); err != nil || pos != int64(len(plaintext)-3) {
		t.Fatalf("SeekEnd(-3) = %d, %v", pos, err)
	}
}

// TestOpenSFSEReader_PlainLenOverflowGuard covers the plainLen range check:
// a negative value or one past maxSFSEPlainLen must be rejected up front,
// before any int64 arithmetic elsewhere in OpenSFSEReader (totalChunks *
// encChunkSize and friends) gets a chance to overflow on a forged value.
func TestOpenSFSEReader_PlainLenOverflowGuard(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := randomPlaintext(t, 64)
	data := buildSFSE2(t, plaintext, 16, testSFSEReaderKey, encFileID)

	tests := []struct {
		name     string
		plainLen int64
	}{
		{"negative", -1},
		{"way negative", -(1 << 60)},
		{"just over the cap", maxSFSEPlainLen + 1},
		{"way over the cap", 1 << 62},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, fi := writeSFSEFile(t, "overflow.sfse", data)
			_, err := OpenSFSEReader(f, fi, testSFSEReaderKey, encFileID, tt.plainLen, "")
			if err == nil {
				t.Fatalf("OpenSFSEReader(plainLen=%d): want error, got nil", tt.plainLen)
			}
		})
	}
}
