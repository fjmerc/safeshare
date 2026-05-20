package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// SH-2.1 / ADR-011 — SFSE2 streaming encryption format.
//
// This file exercises the new V2 path independently of the legacy V1 tests
// in encryption_test.go. Tests live here (not in that file) so a future
// refactor to remove V1 leaves the test surface easy to delete in one cut.

const testKeyV2 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestEncFileID(t *testing.T) []byte {
	t.Helper()
	id, err := GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	if len(id) != SFSE2EncFileIDSize {
		t.Fatalf("GenerateEncFileID returned %d bytes, want %d", len(id), SFSE2EncFileIDSize)
	}
	return id
}

func encryptV2ToTemp(t *testing.T, plaintext []byte, encFileID []byte) string {
	t.Helper()
	dir := t.TempDir()
	encPath := filepath.Join(dir, "enc.sfse2")
	dst, err := os.Create(encPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := EncryptFileStreamingV2FromReader(dst, bytes.NewReader(plaintext), testKeyV2, encFileID, int64(len(plaintext))); err != nil {
		dst.Close()
		t.Fatalf("EncryptFileStreamingV2FromReader: %v", err)
	}
	if err := dst.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return encPath
}

func decryptV2ToBuffer(t *testing.T, encPath string, encFileID []byte, expectedSHA256Hex string) []byte {
	t.Helper()
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.bin")
	// Use -1 for expectedPlaintextLen so the helper accepts any header value;
	// individual tests that care about plaintext-length enforcement call the
	// underlying function directly.
	if err := DecryptFileStreamingV2(encPath, plainPath, testKeyV2, encFileID, expectedSHA256Hex, -1); err != nil {
		t.Fatalf("DecryptFileStreamingV2: %v", err)
	}
	data, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	return data
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// --- Round-trip coverage ----------------------------------------------------

func TestSFSE2_RoundTrip_SingleSmallChunk(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := bytes.Repeat([]byte("hello safeshare "), 100) // 1600 bytes — fits one chunk
	encPath := encryptV2ToTemp(t, plaintext, encFileID)
	got := decryptV2ToBuffer(t, encPath, encFileID, sha256Hex(plaintext))
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(plaintext))
	}
}

func TestSFSE2_RoundTrip_MultiChunk(t *testing.T) {
	encFileID := newTestEncFileID(t)
	// 2.5 chunks => 3 chunks total, with the final one short.
	plaintext := make([]byte, DefaultChunkSize*2+DefaultChunkSize/2)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	encPath := encryptV2ToTemp(t, plaintext, encFileID)
	got := decryptV2ToBuffer(t, encPath, encFileID, sha256Hex(plaintext))
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("multi-chunk round-trip mismatch")
	}
}

func TestSFSE2_RoundTrip_ZeroByte(t *testing.T) {
	encFileID := newTestEncFileID(t)
	encPath := encryptV2ToTemp(t, nil, encFileID)

	// Verify on-disk shape: header only, no chunk bytes.
	info, err := os.Stat(encPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != SFSE2HeaderSize {
		t.Fatalf("zero-byte SFSE2 file size = %d, want %d (header only)", info.Size(), SFSE2HeaderSize)
	}

	got := decryptV2ToBuffer(t, encPath, encFileID, sha256Hex(nil))
	if len(got) != 0 {
		t.Fatalf("zero-byte round-trip returned %d bytes, want 0", len(got))
	}
}

func TestSFSE2_RoundTrip_ExactChunkBoundary(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := bytes.Repeat([]byte("a"), DefaultChunkSize) // exactly one chunk
	encPath := encryptV2ToTemp(t, plaintext, encFileID)
	got := decryptV2ToBuffer(t, encPath, encFileID, sha256Hex(plaintext))
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("exact-chunk-boundary round-trip mismatch")
	}
}

// --- Tamper detection -------------------------------------------------------

func TestSFSE2_Tamper_TruncateLastChunk(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := make([]byte, DefaultChunkSize*2+DefaultChunkSize/2)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	encPath := encryptV2ToTemp(t, plaintext, encFileID)

	// Delete the entire final chunk by truncating the file by (finalChunkBytes + nonce + tag).
	info, _ := os.Stat(encPath)
	encChunkOverhead := int64(12 + 16)
	finalChunkPlain := int64(DefaultChunkSize / 2)
	if err := os.Truncate(encPath, info.Size()-finalChunkPlain-encChunkOverhead); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	dir := t.TempDir()
	err := DecryptFileStreamingV2(encPath, filepath.Join(dir, "plain.bin"), testKeyV2, encFileID, "", -1)
	if err == nil {
		t.Fatal("expected error on truncated SFSE2 file, got nil")
	}
	// The structural file-size check fires before AAD has a chance to run.
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("expected ErrSFSE2IntegrityCheckFailed, got %v", err)
	}
}

func TestSFSE2_Tamper_ReorderChunks(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := make([]byte, DefaultChunkSize*3) // 3 full chunks
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}
	encPath := encryptV2ToTemp(t, plaintext, encFileID)

	raw, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("read enc: %v", err)
	}

	encChunkSize := DefaultChunkSize + 12 + 16
	chunk0Start := SFSE2HeaderSize
	chunk1Start := chunk0Start + encChunkSize

	// Swap chunks 0 and 1 in-place. Both are the same length so this is just a byte-block swap.
	chunk0 := append([]byte(nil), raw[chunk0Start:chunk1Start]...)
	chunk1 := append([]byte(nil), raw[chunk1Start:chunk1Start+encChunkSize]...)
	copy(raw[chunk0Start:chunk1Start], chunk1)
	copy(raw[chunk1Start:chunk1Start+encChunkSize], chunk0)

	if err := os.WriteFile(encPath, raw, 0600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	dir := t.TempDir()
	err = DecryptFileStreamingV2(encPath, filepath.Join(dir, "plain.bin"), testKeyV2, encFileID, "", -1)
	if err == nil {
		t.Fatal("expected error on reordered SFSE2 chunks, got nil")
	}
	// AAD mismatch surfaces as gcm.Open error wrapped with chunk context.
}

func TestSFSE2_Tamper_CrossFileSplice(t *testing.T) {
	plaintextA := bytes.Repeat([]byte("AAAA"), DefaultChunkSize/4)
	plaintextB := bytes.Repeat([]byte("BBBB"), DefaultChunkSize/4)
	encFileIDA := newTestEncFileID(t)
	encFileIDB := newTestEncFileID(t)

	encPathA := encryptV2ToTemp(t, plaintextA, encFileIDA)
	encPathB := encryptV2ToTemp(t, plaintextB, encFileIDB)

	rawA, _ := os.ReadFile(encPathA)
	rawB, _ := os.ReadFile(encPathB)

	// Same chunk layout for both (single chunk; encChunkSize = plaintext_len + 28).
	encChunkSizeA := len(plaintextA) + 12 + 16
	encChunkSizeB := len(plaintextB) + 12 + 16
	if encChunkSizeA != encChunkSizeB {
		t.Fatalf("test bug: chunk sizes differ A=%d B=%d", encChunkSizeA, encChunkSizeB)
	}

	// Replace A's lone chunk with B's lone chunk; both files keep their
	// own headers (so total_plaintext_len matches A's plaintext length).
	copy(rawA[SFSE2HeaderSize:], rawB[SFSE2HeaderSize:])
	if err := os.WriteFile(encPathA, rawA, 0600); err != nil {
		t.Fatalf("write spliced: %v", err)
	}

	dir := t.TempDir()
	err := DecryptFileStreamingV2(encPathA, filepath.Join(dir, "plain.bin"), testKeyV2, encFileIDA, "", -1)
	if err == nil {
		t.Fatal("expected error on cross-file splice, got nil")
	}
}

func TestSFSE2_Tamper_HeaderPlaintextLen(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := bytes.Repeat([]byte("x"), DefaultChunkSize/4)
	encPath := encryptV2ToTemp(t, plaintext, encFileID)

	// Overwrite total_plaintext_len in the header with a wildly wrong value.
	raw, _ := os.ReadFile(encPath)
	binary.BigEndian.PutUint64(raw[10:18], uint64(len(plaintext)*2))
	if err := os.WriteFile(encPath, raw, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	dir := t.TempDir()
	err := DecryptFileStreamingV2(encPath, filepath.Join(dir, "plain.bin"), testKeyV2, encFileID, "", -1)
	if err == nil {
		t.Fatal("expected error on header total_plaintext_len tamper, got nil")
	}
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("expected ErrSFSE2IntegrityCheckFailed, got %v", err)
	}
}

func TestSFSE2_Tamper_FlipCiphertextBit(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := bytes.Repeat([]byte("z"), 500)
	encPath := encryptV2ToTemp(t, plaintext, encFileID)

	raw, _ := os.ReadFile(encPath)
	// Flip a byte inside the first chunk's ciphertext (past nonce).
	raw[SFSE2HeaderSize+20] ^= 0xFF
	if err := os.WriteFile(encPath, raw, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	dir := t.TempDir()
	err := DecryptFileStreamingV2(encPath, filepath.Join(dir, "plain.bin"), testKeyV2, encFileID, "", -1)
	if err == nil {
		t.Fatal("expected gcm.Open error on flipped ciphertext, got nil")
	}
}

func TestSFSE2_Tamper_SHA256Mismatch(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := bytes.Repeat([]byte("ok"), 100)
	encPath := encryptV2ToTemp(t, plaintext, encFileID)

	// Pass a deliberately wrong SHA-256 to force the post-decrypt verify to fail.
	wrongSHA := sha256Hex([]byte("not the actual plaintext"))
	dir := t.TempDir()
	err := DecryptFileStreamingV2(encPath, filepath.Join(dir, "plain.bin"), testKeyV2, encFileID, wrongSHA, -1)
	if err == nil {
		t.Fatal("expected SHA-256 mismatch error, got nil")
	}
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("expected ErrSFSE2IntegrityCheckFailed, got %v", err)
	}
}

// TestSFSE2_Tamper_ZeroByteCollapse is the regression test for the bug-hunter
// m-2 finding: a storage-write attacker truncates a non-empty SFSE2 file to
// header-only and rewrites total_plaintext_len=0 to make a non-empty file
// appear legitimately empty. Without the expectedPlaintextLen parameter, the
// SFSE2 layer surfaces no integrity error and the response would silently
// turn into 0 bytes. With it, the decrypt is rejected before any chunk work.
func TestSFSE2_Tamper_ZeroByteCollapse(t *testing.T) {
	encFileID := newTestEncFileID(t)
	originalPlaintext := bytes.Repeat([]byte("genuine content "), 100) // 1600 bytes
	encPath := encryptV2ToTemp(t, originalPlaintext, encFileID)

	// Attacker truncates to header-only (18 bytes) and rewrites the
	// total_plaintext_len trailer to 0.
	if err := os.Truncate(encPath, SFSE2HeaderSize); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	raw, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	binary.BigEndian.PutUint64(raw[10:18], 0)
	if err := os.WriteFile(encPath, raw, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	dir := t.TempDir()

	// Without expectedPlaintextLen the attack succeeds at the SFSE2 layer:
	// the reader returns (0, nil) for what looks like a valid empty file.
	if err := DecryptFileStreamingV2(encPath, filepath.Join(dir, "plain_undefended.bin"), testKeyV2, encFileID, "", -1); err != nil {
		t.Fatalf("unexpected error without length check: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "plain_undefended.bin"))
	if len(got) != 0 {
		t.Fatalf("expected 0 bytes (the attack), got %d", len(got))
	}

	// With expectedPlaintextLen == original size the attack must be rejected.
	err = DecryptFileStreamingV2(encPath, filepath.Join(dir, "plain_defended.bin"), testKeyV2, encFileID, "", int64(len(originalPlaintext)))
	if err == nil {
		t.Fatal("expected ErrSFSE2IntegrityCheckFailed when caller supplies expected length, got nil")
	}
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("expected ErrSFSE2IntegrityCheckFailed, got %v", err)
	}
}

// TestSFSE2_LengthCheck_RejectsMismatch confirms that any header-length
// disagreement (not just zero) is rejected when the caller supplies
// expectedPlaintextLen.
func TestSFSE2_LengthCheck_RejectsMismatch(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := bytes.Repeat([]byte("x"), 1024)
	encPath := encryptV2ToTemp(t, plaintext, encFileID)

	dir := t.TempDir()
	// Truth is 1024 bytes; caller asserts 2048. Must fail before any decrypt.
	err := DecryptFileStreamingV2(encPath, filepath.Join(dir, "out.bin"), testKeyV2, encFileID, "", 2048)
	if err == nil || !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("expected ErrSFSE2IntegrityCheckFailed on length mismatch, got %v", err)
	}

	// Truth matches caller expectation: decrypt succeeds.
	if err := DecryptFileStreamingV2(encPath, filepath.Join(dir, "ok.bin"), testKeyV2, encFileID, "", int64(len(plaintext))); err != nil {
		t.Fatalf("matching length should succeed, got %v", err)
	}
}

func TestSFSE2_Tamper_WrongEncFileID(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := []byte("payload")
	encPath := encryptV2ToTemp(t, plaintext, encFileID)

	otherID := newTestEncFileID(t)
	dir := t.TempDir()
	err := DecryptFileStreamingV2(encPath, filepath.Join(dir, "plain.bin"), testKeyV2, otherID, "", -1)
	if err == nil {
		t.Fatal("expected AAD failure with wrong enc_file_id, got nil")
	}
}

// --- Range reader -----------------------------------------------------------

func TestSFSE2_Range_MultipleSubranges(t *testing.T) {
	encFileID := newTestEncFileID(t)
	plaintext := make([]byte, DefaultChunkSize*2+1000)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}
	encPath := encryptV2ToTemp(t, plaintext, encFileID)

	cases := []struct {
		name       string
		start, end int64
	}{
		{"prefix in first chunk", 0, 999},
		{"crosses chunk boundary", int64(DefaultChunkSize) - 5, int64(DefaultChunkSize) + 4},
		{"middle of second chunk", int64(DefaultChunkSize) + 100, int64(DefaultChunkSize) + 199},
		{"tail through last chunk", int64(DefaultChunkSize)*2 - 50, int64(len(plaintext)) - 1},
		{"single byte mid-file", int64(DefaultChunkSize), int64(DefaultChunkSize)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := DecryptFileStreamingRangeV2(encPath, &buf, testKeyV2, encFileID, "", -1, c.start, c.end)
			if err != nil {
				t.Fatalf("Range[%d..%d]: %v", c.start, c.end, err)
			}
			want := plaintext[c.start : c.end+1]
			if int64(len(want)) != n {
				t.Fatalf("Range[%d..%d]: wrote %d, want %d", c.start, c.end, n, len(want))
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Fatalf("Range[%d..%d]: content mismatch", c.start, c.end)
			}
		})
	}
}

func TestSFSE2_Range_DetectsSpliceInTouchedChunk(t *testing.T) {
	// Range reads can't detect truncation past the requested window, but they
	// MUST detect splice/reorder of any chunk they touch.
	plaintextA := make([]byte, DefaultChunkSize*2)
	plaintextB := make([]byte, DefaultChunkSize*2)
	for i := range plaintextA {
		plaintextA[i] = 'A'
		plaintextB[i] = 'B'
	}
	encFileIDA := newTestEncFileID(t)
	encFileIDB := newTestEncFileID(t)
	encPathA := encryptV2ToTemp(t, plaintextA, encFileIDA)
	encPathB := encryptV2ToTemp(t, plaintextB, encFileIDB)

	rawA, _ := os.ReadFile(encPathA)
	rawB, _ := os.ReadFile(encPathB)
	encChunkSize := DefaultChunkSize + 12 + 16

	// Splice B's chunk 0 into A.
	copy(rawA[SFSE2HeaderSize:SFSE2HeaderSize+encChunkSize], rawB[SFSE2HeaderSize:SFSE2HeaderSize+encChunkSize])
	if err := os.WriteFile(encPathA, rawA, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Range request that touches the spliced chunk → must fail.
	var buf bytes.Buffer
	_, err := DecryptFileStreamingRangeV2(encPathA, &buf, testKeyV2, encFileIDA, "", -1, 0, 100)
	if err == nil {
		t.Fatal("expected Range read to fail on spliced chunk, got nil")
	}
}

// --- Version dispatcher -----------------------------------------------------

func TestSFSE_Dispatcher_RoutesV1AndV2(t *testing.T) {
	dir := t.TempDir()

	// Write a V1 (legacy) file with the existing writer.
	v1Plain := bytes.Repeat([]byte("v1"), 200)
	v1PlainPath := filepath.Join(dir, "v1_plain.bin")
	v1EncPath := filepath.Join(dir, "v1_enc.bin")
	if err := os.WriteFile(v1PlainPath, v1Plain, 0600); err != nil {
		t.Fatalf("write v1 plain: %v", err)
	}
	if err := EncryptFileStreaming(v1PlainPath, v1EncPath, testKeyV2); err != nil {
		t.Fatalf("EncryptFileStreaming (V1): %v", err)
	}

	// Write a V2 file.
	encFileID := newTestEncFileID(t)
	v2Plain := bytes.Repeat([]byte("v2"), 300)
	v2EncPath := encryptV2ToTemp(t, v2Plain, encFileID)

	// Sanity-check the peek function.
	if ver, err := PeekSFSEVersion(v1EncPath); err != nil || ver != StreamEncryptionVersion {
		t.Fatalf("PeekSFSEVersion(v1) = (%d, %v)", ver, err)
	}
	if ver, err := PeekSFSEVersion(v2EncPath); err != nil || ver != StreamEncryptionVersionV2 {
		t.Fatalf("PeekSFSEVersion(v2) = (%d, %v)", ver, err)
	}

	// Dispatch reads.
	outV1 := filepath.Join(dir, "v1_out.bin")
	if err := DecryptFileStreamingAny(v1EncPath, outV1, testKeyV2, nil, "", -1); err != nil {
		t.Fatalf("DecryptFileStreamingAny(v1): %v", err)
	}
	got, _ := os.ReadFile(outV1)
	if !bytes.Equal(got, v1Plain) {
		t.Fatalf("V1 dispatcher round-trip mismatch")
	}

	outV2 := filepath.Join(dir, "v2_out.bin")
	if err := DecryptFileStreamingAny(v2EncPath, outV2, testKeyV2, encFileID, sha256Hex(v2Plain), int64(len(v2Plain))); err != nil {
		t.Fatalf("DecryptFileStreamingAny(v2): %v", err)
	}
	got, _ = os.ReadFile(outV2)
	if !bytes.Equal(got, v2Plain) {
		t.Fatalf("V2 dispatcher round-trip mismatch")
	}

	// Range dispatch.
	var buf bytes.Buffer
	n, err := DecryptFileStreamingRangeAny(v1EncPath, &buf, testKeyV2, nil, "", -1, 0, 9)
	if err != nil {
		t.Fatalf("Range(v1): %v", err)
	}
	if n != 10 || !bytes.Equal(buf.Bytes(), v1Plain[:10]) {
		t.Fatalf("Range(v1) mismatch: n=%d, got=%q", n, buf.Bytes())
	}
	buf.Reset()
	n, err = DecryptFileStreamingRangeAny(v2EncPath, &buf, testKeyV2, encFileID, "", int64(len(v2Plain)), 0, 9)
	if err != nil {
		t.Fatalf("Range(v2): %v", err)
	}
	if n != 10 || !bytes.Equal(buf.Bytes(), v2Plain[:10]) {
		t.Fatalf("Range(v2) mismatch: n=%d, got=%q", n, buf.Bytes())
	}
}

func TestSFSE_Dispatcher_RejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "bogus.sfse")
	// SFSE1 magic + version 0xFF + 8 zero bytes.
	hdr := append([]byte(StreamEncryptionMagic), 0xFF)
	hdr = append(hdr, make([]byte, 12)...)
	if err := os.WriteFile(bogus, hdr, 0600); err != nil {
		t.Fatalf("write bogus: %v", err)
	}

	if _, err := PeekSFSEVersion(bogus); err != nil {
		t.Fatalf("PeekSFSEVersion: %v", err)
	}
	err := DecryptFileStreamingAny(bogus, filepath.Join(dir, "out.bin"), testKeyV2, nil, "", -1)
	if err == nil || !errors.Is(err, ErrUnsupportedSFSEVersion) {
		t.Fatalf("expected ErrUnsupportedSFSEVersion, got %v", err)
	}
}

// --- Constructor argument validation ---------------------------------------

func TestSFSE2_Writer_RejectsBadEncFileID(t *testing.T) {
	var buf bytes.Buffer
	for _, badID := range [][]byte{nil, make([]byte, 0), make([]byte, 8), make([]byte, 32)} {
		err := EncryptFileStreamingV2FromReader(&buf, bytes.NewReader([]byte("x")), testKeyV2, badID, 1)
		if err == nil {
			t.Fatalf("expected error on enc_file_id len=%d, got nil", len(badID))
		}
	}
}

func TestSFSE2_Writer_RejectsNegativeLength(t *testing.T) {
	encFileID := newTestEncFileID(t)
	var buf bytes.Buffer
	err := EncryptFileStreamingV2FromReader(&buf, bytes.NewReader(nil), testKeyV2, encFileID, -1)
	if err == nil {
		t.Fatal("expected error on negative plaintextLen, got nil")
	}
}

func TestSFSE2_Writer_DetectsShortPlaintext(t *testing.T) {
	encFileID := newTestEncFileID(t)
	var buf bytes.Buffer
	// Caller declares 1000 but supplies only 500 bytes.
	err := EncryptFileStreamingV2FromReader(&buf, io.LimitReader(bytes.NewReader(bytes.Repeat([]byte("a"), 500)), 500), testKeyV2, encFileID, 1000)
	if err == nil {
		t.Fatal("expected error when plaintext shorter than declared, got nil")
	}
}

// --- buildSFSE2AAD unit ----------------------------------------------------

func TestSFSE2_BuildAAD_Layout(t *testing.T) {
	id := bytes.Repeat([]byte{0x42}, SFSE2EncFileIDSize)
	aad, err := buildSFSE2AAD(id, 0x0102030405060708, true)
	if err != nil {
		t.Fatalf("buildSFSE2AAD: %v", err)
	}
	if len(aad) != sfse2AADSize {
		t.Fatalf("AAD length = %d, want %d", len(aad), sfse2AADSize)
	}
	if !bytes.Equal(aad[:SFSE2EncFileIDSize], id) {
		t.Fatalf("AAD enc_file_id mismatch")
	}
	if binary.BigEndian.Uint64(aad[SFSE2EncFileIDSize:SFSE2EncFileIDSize+8]) != 0x0102030405060708 {
		t.Fatalf("AAD chunk_index encoding wrong")
	}
	if aad[SFSE2EncFileIDSize+8] != sfse2FlagIsLast {
		t.Fatalf("AAD is_last flag not set")
	}

	aad2, err := buildSFSE2AAD(id, 0, false)
	if err != nil {
		t.Fatalf("buildSFSE2AAD: %v", err)
	}
	if aad2[SFSE2EncFileIDSize+8] != 0 {
		t.Fatalf("AAD flags should be zero, got %#x", aad2[SFSE2EncFileIDSize+8])
	}
}
