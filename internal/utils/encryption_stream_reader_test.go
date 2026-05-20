package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

// readerTestKey is a deterministic 32-byte hex key used across the
// reader-based decrypt tests. Production deployments must use a random key.
const readerTestKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func mustGenEncFileID(t *testing.T) []byte {
	t.Helper()
	id, err := GenerateEncFileID()
	if err != nil {
		t.Fatalf("GenerateEncFileID: %v", err)
	}
	return id
}

func mustEncryptV2(t *testing.T, plaintext []byte, encFileID []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := EncryptFileStreamingV2FromReader(&buf, bytes.NewReader(plaintext), readerTestKey, encFileID, int64(len(plaintext))); err != nil {
		t.Fatalf("EncryptFileStreamingV2FromReader: %v", err)
	}
	return buf.Bytes()
}

// TestDecryptSFSE2FromReader_RoundTrip exercises the reader-based V2 full
// decrypt against a freshly-encrypted blob and asserts byte-exact plaintext
// recovery plus SHA-256 verification when the caller supplies a hash.
func TestDecryptSFSE2FromReader_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"single byte", 1},
		{"small (<1 chunk)", 1024},
		{"chunk boundary - 1", DefaultChunkSize - 1},
		{"exact chunk", DefaultChunkSize},
		{"chunk boundary + 1", DefaultChunkSize + 1},
		{"2.5 chunks", DefaultChunkSize*5/2 + 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := make([]byte, tt.size)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatalf("rand: %v", err)
			}
			encFileID := mustGenEncFileID(t)
			ct := mustEncryptV2(t, plaintext, encFileID)

			sum := sha256.Sum256(plaintext)
			sumHex := hex.EncodeToString(sum[:])

			var out bytes.Buffer
			n, err := DecryptSFSE2FromReader(bytes.NewReader(ct), &out, readerTestKey, encFileID, sumHex, int64(tt.size), int64(len(ct)))
			if err != nil {
				t.Fatalf("DecryptSFSE2FromReader: %v", err)
			}
			if n != int64(tt.size) {
				t.Errorf("written = %d, want %d", n, tt.size)
			}
			if !bytes.Equal(out.Bytes(), plaintext) {
				t.Errorf("plaintext mismatch")
			}
		})
	}
}

// TestDecryptSFSE2FromReader_EncryptedSizeMismatch proves that passing an
// `encryptedSize` that disagrees with the SFSE2 header trailer fires the
// fast-fail size check before any chunk decrypt happens.
func TestDecryptSFSE2FromReader_EncryptedSizeMismatch(t *testing.T) {
	plaintext := bytes.Repeat([]byte("A"), 1024)
	encFileID := mustGenEncFileID(t)
	ct := mustEncryptV2(t, plaintext, encFileID)

	// Real encryptedSize is len(ct). Pass len(ct)+1 to trip the mismatch.
	var out bytes.Buffer
	_, err := DecryptSFSE2FromReader(bytes.NewReader(ct), &out, readerTestKey, encFileID, "", int64(len(plaintext)), int64(len(ct))+1)
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("expected ErrSFSE2IntegrityCheckFailed, got %v", err)
	}
}

// TestDecryptSFSE2FromReader_PlaintextLenMismatch proves the
// expectedPlaintextLen cross-check fires before any chunk decrypt.
func TestDecryptSFSE2FromReader_PlaintextLenMismatch(t *testing.T) {
	plaintext := bytes.Repeat([]byte("B"), 100)
	encFileID := mustGenEncFileID(t)
	ct := mustEncryptV2(t, plaintext, encFileID)

	var out bytes.Buffer
	_, err := DecryptSFSE2FromReader(bytes.NewReader(ct), &out, readerTestKey, encFileID, "", 200, -1)
	if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Fatalf("expected ErrSFSE2IntegrityCheckFailed, got %v", err)
	}
}

// TestDecryptSFSE2FromReader_WrongEncFileID proves a swapped enc_file_id
// fails AAD validation (wrapping gcm.Open's error, not
// ErrSFSE2IntegrityCheckFailed).
func TestDecryptSFSE2FromReader_WrongEncFileID(t *testing.T) {
	plaintext := []byte("hello")
	realID := mustGenEncFileID(t)
	wrongID := mustGenEncFileID(t)
	ct := mustEncryptV2(t, plaintext, realID)

	var out bytes.Buffer
	_, err := DecryptSFSE2FromReader(bytes.NewReader(ct), &out, readerTestKey, wrongID, "", -1, -1)
	if err == nil {
		t.Fatal("expected AAD failure, got nil")
	}
	// Should NOT be the integrity-check sentinel — the failure is the GCM
	// open call's wrapped error.
	if errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
		t.Errorf("unexpected ErrSFSE2IntegrityCheckFailed; expected gcm.Open failure path: %v", err)
	}
}

// TestDecryptSFSE2RangeFromReader exercises the range API across each
// position class: first chunk only, last chunk only, straddling, and a
// single byte at chunk_size boundary.
func TestDecryptSFSE2RangeFromReader(t *testing.T) {
	plaintext := make([]byte, DefaultChunkSize*3+1024)
	for i := range plaintext {
		plaintext[i] = byte(i & 0xff)
	}
	encFileID := mustGenEncFileID(t)
	ct := mustEncryptV2(t, plaintext, encFileID)

	chunkSize := int64(DefaultChunkSize)
	totalLen := int64(len(plaintext))

	cases := []struct {
		name    string
		pStart  int64
		pEnd    int64
	}{
		{"first chunk only", 0, chunkSize - 1},
		{"first chunk middle", 100, 1024 + 100 - 1},
		{"second chunk only", chunkSize, 2*chunkSize - 1},
		{"straddle 1-2", chunkSize - 100, chunkSize + 100},
		{"last chunk only (partial)", 3 * chunkSize, totalLen - 1},
		{"single byte at chunk boundary", chunkSize, chunkSize},
		{"single byte at last byte", totalLen - 1, totalLen - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctStart, ctEnd, err := ComputeSFSE2CiphertextRange(tc.pStart, tc.pEnd, chunkSize, totalLen)
			if err != nil {
				t.Fatalf("ComputeSFSE2CiphertextRange: %v", err)
			}
			if ctEnd < ctStart || ctEnd >= int64(len(ct)) {
				t.Fatalf("computed ct range [%d, %d] out of bounds for ct len %d", ctStart, ctEnd, len(ct))
			}
			body := bytes.NewReader(ct[ctStart : ctEnd+1])

			var out bytes.Buffer
			n, err := DecryptSFSE2RangeFromReader(body, &out, readerTestKey, encFileID, "", chunkSize, totalLen, tc.pStart, tc.pEnd)
			if err != nil {
				t.Fatalf("DecryptSFSE2RangeFromReader: %v", err)
			}
			want := plaintext[tc.pStart : tc.pEnd+1]
			if n != int64(len(want)) {
				t.Errorf("wrote %d, want %d", n, len(want))
			}
			if !bytes.Equal(out.Bytes(), want) {
				t.Errorf("range bytes mismatch at [%d, %d]", tc.pStart, tc.pEnd)
			}
		})
	}
}

// TestDecryptSFSEFromReader_DispatchesV1 proves the version-byte dispatcher
// correctly routes V1 (legacy SFSE1) blobs to the no-AAD decrypt path. V1
// is emitted by EncryptFileStreamingFromReader (the pre-SH-2.1 writer).
func TestDecryptSFSEFromReader_DispatchesV1(t *testing.T) {
	plaintext := bytes.Repeat([]byte("V1!"), 5_000_000)
	var enc bytes.Buffer
	if err := EncryptFileStreamingFromReader(&enc, bytes.NewReader(plaintext), readerTestKey); err != nil {
		t.Fatalf("EncryptFileStreamingFromReader: %v", err)
	}

	var out bytes.Buffer
	encFileID := mustGenEncFileID(t) // ignored for V1
	n, err := DecryptSFSEFromReader(bytes.NewReader(enc.Bytes()), &out, readerTestKey, encFileID, "", -1, -1)
	if err != nil {
		t.Fatalf("DecryptSFSEFromReader (V1): %v", err)
	}
	if n != int64(len(plaintext)) {
		t.Errorf("wrote %d, want %d", n, len(plaintext))
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Errorf("V1 round-trip mismatch")
	}
}

// TestDecryptSFSEFromReader_DispatchesV2 proves the version-byte dispatcher
// correctly routes V2 (SFSE2) blobs and that the encFileID/lengths are
// honored.
func TestDecryptSFSEFromReader_DispatchesV2(t *testing.T) {
	plaintext := []byte("hello from V2")
	encFileID := mustGenEncFileID(t)
	ct := mustEncryptV2(t, plaintext, encFileID)
	sum := sha256.Sum256(plaintext)

	var out bytes.Buffer
	n, err := DecryptSFSEFromReader(bytes.NewReader(ct), &out, readerTestKey, encFileID, hex.EncodeToString(sum[:]), int64(len(plaintext)), int64(len(ct)))
	if err != nil {
		t.Fatalf("DecryptSFSEFromReader (V2): %v", err)
	}
	if n != int64(len(plaintext)) || !bytes.Equal(out.Bytes(), plaintext) {
		t.Errorf("V2 dispatcher round-trip mismatch")
	}
}

// TestDecryptSFSEFromReader_RejectsBadMagic asserts that arbitrary input
// without the SFSE magic is rejected before any cipher operations.
func TestDecryptSFSEFromReader_RejectsBadMagic(t *testing.T) {
	junk := []byte("this is not encrypted at all, definitely not SFSE")
	var out bytes.Buffer
	_, err := DecryptSFSEFromReader(bytes.NewReader(junk), &out, readerTestKey, make([]byte, SFSE2EncFileIDSize), "", -1, -1)
	if err == nil {
		t.Fatal("expected error for non-SFSE input")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("expected magic error, got %v", err)
	}
}

// TestDecryptSFSEFromReader_RejectsUnknownVersion asserts that a forged
// version byte fails closed with ErrUnsupportedSFSEVersion.
func TestDecryptSFSEFromReader_RejectsUnknownVersion(t *testing.T) {
	hdr := append([]byte(StreamEncryptionMagic), 0xFF) // version=0xFF
	var out bytes.Buffer
	_, err := DecryptSFSEFromReader(bytes.NewReader(hdr), &out, readerTestKey, make([]byte, SFSE2EncFileIDSize), "", -1, -1)
	if !errors.Is(err, ErrUnsupportedSFSEVersion) {
		t.Fatalf("expected ErrUnsupportedSFSEVersion, got %v", err)
	}
}

// TestComputeSFSE2CiphertextRange_ConsistentWithEncoding asserts that the
// ranges produced by ComputeSFSE2CiphertextRange always cover the exact
// ciphertext bytes that DecryptSFSE2RangeFromReader needs to consume. This
// is the contract S3 wrappers rely on — if these drift, S3 Range fetches
// would over- or under-fetch.
func TestComputeSFSE2CiphertextRange_ConsistentWithEncoding(t *testing.T) {
	plaintext := make([]byte, DefaultChunkSize*2+1234)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	encFileID := mustGenEncFileID(t)
	ct := mustEncryptV2(t, plaintext, encFileID)
	chunkSize := int64(DefaultChunkSize)
	plLen := int64(len(plaintext))

	// Take 50 pseudo-random ranges across the file and assert end-to-end
	// consistency between the computed ct range and the actual decrypt.
	for i := 0; i < 50; i++ {
		pStart := int64(i * 47 % int(plLen))
		pEnd := pStart + int64((i*131+1)%int(plLen-pStart))
		if pEnd >= plLen {
			pEnd = plLen - 1
		}
		ctStart, ctEnd, err := ComputeSFSE2CiphertextRange(pStart, pEnd, chunkSize, plLen)
		if err != nil {
			t.Fatalf("ComputeSFSE2CiphertextRange(%d, %d): %v", pStart, pEnd, err)
		}
		var out bytes.Buffer
		n, err := DecryptSFSE2RangeFromReader(
			bytes.NewReader(ct[ctStart:ctEnd+1]), &out,
			readerTestKey, encFileID, "", chunkSize, plLen, pStart, pEnd)
		if err != nil {
			t.Fatalf("DecryptSFSE2RangeFromReader iter=%d range=[%d, %d] ct=[%d, %d]: %v",
				i, pStart, pEnd, ctStart, ctEnd, err)
		}
		want := plaintext[pStart : pEnd+1]
		if n != int64(len(want)) || !bytes.Equal(out.Bytes(), want) {
			t.Errorf("iter=%d range=[%d, %d] mismatch: got %d bytes, want %d",
				i, pStart, pEnd, n, len(want))
		}
	}
}

// TestDecryptSFSE2FromReader_EmptyPlaintext covers the zero-byte edge case:
// the SFSE2 writer emits only the header and the reader returns 0 bytes
// with no error.
func TestDecryptSFSE2FromReader_EmptyPlaintext(t *testing.T) {
	encFileID := mustGenEncFileID(t)
	ct := mustEncryptV2(t, nil, encFileID)
	if len(ct) != SFSE2HeaderSize {
		t.Fatalf("empty plaintext ciphertext = %d bytes, want %d (header only)", len(ct), SFSE2HeaderSize)
	}
	var out bytes.Buffer
	n, err := DecryptSFSE2FromReader(bytes.NewReader(ct), &out, readerTestKey, encFileID, "", 0, int64(len(ct)))
	if err != nil {
		t.Fatalf("DecryptSFSE2FromReader empty: %v", err)
	}
	if n != 0 || out.Len() != 0 {
		t.Errorf("expected zero bytes, got n=%d, out.Len=%d", n, out.Len())
	}
}

// TestDecryptSFSE1RangeFromReader exercises the V1 (no-AAD) range decrypt
// against a V1 blob produced by EncryptFileStreamingFromReader. Covers
// straddling and last-chunk-only cases.
func TestDecryptSFSE1RangeFromReader(t *testing.T) {
	plaintext := bytes.Repeat([]byte("0123456789"), 1_100_000) // 11 MB — spans 2 chunks
	var enc bytes.Buffer
	if err := EncryptFileStreamingFromReader(&enc, bytes.NewReader(plaintext), readerTestKey); err != nil {
		t.Fatalf("EncryptFileStreamingFromReader: %v", err)
	}
	chunkSize := int64(DefaultChunkSize)
	encChunkSize := chunkSize + int64(SFSE2OverheadPerChunk)

	cases := []struct {
		name string
		s, e int64
	}{
		{"first chunk middle", 1000, 2000},
		{"straddle 1-2", chunkSize - 50, chunkSize + 50},
		{"last partial", chunkSize + 1024, int64(len(plaintext)) - 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			startChunk := tc.s / chunkSize
			endChunk := tc.e / chunkSize
			ctStart := int64(SFSE1HeaderSize) + startChunk*encChunkSize
			ctEnd := int64(SFSE1HeaderSize) + (endChunk+1)*encChunkSize - 1
			if ctEnd >= int64(enc.Len()) {
				ctEnd = int64(enc.Len()) - 1
			}
			body := bytes.NewReader(enc.Bytes()[ctStart : ctEnd+1])

			var out bytes.Buffer
			n, err := DecryptSFSE1RangeFromReader(body, &out, readerTestKey, chunkSize, tc.s, tc.e)
			if err != nil {
				t.Fatalf("DecryptSFSE1RangeFromReader: %v", err)
			}
			want := plaintext[tc.s : tc.e+1]
			if n != int64(len(want)) {
				t.Errorf("wrote %d, want %d", n, len(want))
			}
			if !bytes.Equal(out.Bytes(), want) {
				t.Errorf("V1 range bytes mismatch")
			}
		})
	}
}

// TestDecryptSFSE2RangeFromReader_FullRange_TriggersSHACheck proves that a
// Range call covering [0, totalPlaintextLen-1] is internally promoted to a
// fullRead and therefore runs the SHA-256 verification when supplied.
func TestDecryptSFSE2RangeFromReader_FullRange_TriggersSHACheck(t *testing.T) {
	plaintext := bytes.Repeat([]byte{0xAB}, 4096)
	encFileID := mustGenEncFileID(t)
	ct := mustEncryptV2(t, plaintext, encFileID)
	sum := sha256.Sum256(plaintext)
	chunkSize := int64(DefaultChunkSize)
	plLen := int64(len(plaintext))
	ctStart, ctEnd, err := ComputeSFSE2CiphertextRange(0, plLen-1, chunkSize, plLen)
	if err != nil {
		t.Fatalf("ComputeSFSE2CiphertextRange: %v", err)
	}

	t.Run("matching hash succeeds", func(t *testing.T) {
		var out bytes.Buffer
		n, err := DecryptSFSE2RangeFromReader(bytes.NewReader(ct[ctStart:ctEnd+1]), &out, readerTestKey, encFileID, hex.EncodeToString(sum[:]), chunkSize, plLen, 0, plLen-1)
		if err != nil {
			t.Fatalf("range full read: %v", err)
		}
		if n != plLen {
			t.Errorf("wrote %d, want %d", n, plLen)
		}
	})
	t.Run("wrong hash fails", func(t *testing.T) {
		wrong := strings.Repeat("00", sha256.Size)
		var out bytes.Buffer
		_, err := DecryptSFSE2RangeFromReader(bytes.NewReader(ct[ctStart:ctEnd+1]), &out, readerTestKey, encFileID, wrong, chunkSize, plLen, 0, plLen-1)
		if !errors.Is(err, ErrSFSE2IntegrityCheckFailed) {
			t.Errorf("expected ErrSFSE2IntegrityCheckFailed, got %v", err)
		}
	})
}

// TestPrependReader verifies the simple io.Reader helper used to re-prepend
// version-peek bytes when dispatching V1 reads.
func TestPrependReader(t *testing.T) {
	src := []byte("ABCDEF")
	rest := []byte("GHIJKL")
	r := io.MultiReader(prependReader(src), bytes.NewReader(rest))
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := []byte("ABCDEFGHIJKL")
	if !bytes.Equal(got, want) {
		t.Errorf("prependReader concat mismatch: got %q want %q", got, want)
	}
}

// TestComputeSFSE2CiphertextRange_EmptyFile ensures the helper returns an
// invalid (empty) range for zero-byte files without crashing.
func TestComputeSFSE2CiphertextRange_EmptyFile(t *testing.T) {
	ctStart, ctEnd, err := ComputeSFSE2CiphertextRange(0, 0, int64(DefaultChunkSize), 0)
	if err != nil {
		t.Fatalf("unexpected error for empty file: %v", err)
	}
	if ctEnd >= ctStart {
		t.Errorf("expected empty range for zero-byte file, got ctStart=%d ctEnd=%d", ctStart, ctEnd)
	}
}
