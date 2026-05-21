package s3

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/fjmerc/safeshare/internal/utils"
)

// TestNewS3EncryptedStorage tests encrypted storage construction with
// representative key inputs. The construction does not touch S3, so we can
// run it with a no-op backend.
func TestNewS3EncryptedStorage(t *testing.T) {
	backend := &S3Storage{bucket: "test-bucket"}
	tests := []struct {
		name    string
		keyHex  string
		wantErr bool
	}{
		{"valid 32-byte key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false},
		{"empty key", "", true},
		{"invalid hex", "not-valid-hex", true},
		{"too short", "0123456789abcdef", true},
		{"too long", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewS3EncryptedStorage(backend, tt.keyHex)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewS3EncryptedStorage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestParseSFSE2Metadata covers the metadata parser used by Retrieve /
// StreamRange to recover SFSE2 enc_file_id + plaintext_len from S3 object
// UserMetadata. This is hot-path code for every V2 read.
func TestParseSFSE2Metadata(t *testing.T) {
	validID := make([]byte, utils.SFSE2EncFileIDSize)
	for i := range validID {
		validID[i] = byte(i + 1)
	}
	validIDHex := hex.EncodeToString(validID)

	tests := []struct {
		name           string
		meta           map[string]string
		wantOK         bool
		wantID         []byte
		wantPlaintext  int64
		wantOKExplain  string
		wantFailReason string
	}{
		{
			name: "valid V2 metadata",
			meta: map[string]string{
				s3MetaSFSEVersion:       "2",
				s3MetaSFSE2EncFileID:    validIDHex,
				s3MetaSFSE2PlaintextLen: "1048576",
			},
			wantOK:        true,
			wantID:        validID,
			wantPlaintext: 1048576,
		},
		{
			name: "valid V2 metadata with capitalized keys (S3-compat backends)",
			meta: map[string]string{
				"Safeshare-Sfse-Version":          "2",
				"Safeshare-Sfse2-Enc-File-Id":     validIDHex,
				"Safeshare-Sfse2-Plaintext-Len":   "0",
			},
			wantOK:        true,
			wantID:        validID,
			wantPlaintext: 0,
		},
		{
			name: "version=1 (legacy SFSE1)",
			meta: map[string]string{
				s3MetaSFSEVersion: "1",
			},
			wantOK:         false,
			wantFailReason: "V1 metadata should not parse as V2",
		},
		{
			name:           "empty metadata",
			meta:           map[string]string{},
			wantOK:         false,
			wantFailReason: "no metadata present",
		},
		{
			name: "malformed hex enc_file_id",
			meta: map[string]string{
				s3MetaSFSEVersion:       "2",
				s3MetaSFSE2EncFileID:    "not-hex",
				s3MetaSFSE2PlaintextLen: "1024",
			},
			wantOK:         false,
			wantFailReason: "invalid hex should reject",
		},
		{
			name: "wrong-length enc_file_id (8 bytes hex = 16 chars)",
			meta: map[string]string{
				s3MetaSFSEVersion:       "2",
				s3MetaSFSE2EncFileID:    "0123456789abcdef",
				s3MetaSFSE2PlaintextLen: "1024",
			},
			wantOK:         false,
			wantFailReason: "wrong-length enc_file_id should reject",
		},
		{
			name: "negative plaintext_len",
			meta: map[string]string{
				s3MetaSFSEVersion:       "2",
				s3MetaSFSE2EncFileID:    validIDHex,
				s3MetaSFSE2PlaintextLen: "-1",
			},
			wantOK:         false,
			wantFailReason: "negative plaintext_len should reject",
		},
		{
			name: "missing enc_file_id",
			meta: map[string]string{
				s3MetaSFSEVersion:       "2",
				s3MetaSFSE2PlaintextLen: "1024",
			},
			wantOK:         false,
			wantFailReason: "missing enc_file_id should reject",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, plen, ok := parseSFSE2Metadata(tt.meta)
			if ok != tt.wantOK {
				t.Fatalf("parseSFSE2Metadata ok=%v, want %v (%s)", ok, tt.wantOK, tt.wantFailReason)
			}
			if !ok {
				return
			}
			if hex.EncodeToString(id) != hex.EncodeToString(tt.wantID) {
				t.Errorf("enc_file_id = %x, want %x", id, tt.wantID)
			}
			if plen != tt.wantPlaintext {
				t.Errorf("plaintext_len = %d, want %d", plen, tt.wantPlaintext)
			}
		})
	}
}

// TestEqualFold verifies the ASCII case-insensitive comparator used by the
// metadata parser's case-insensitive fallback.
func TestEqualFold(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"safeshare-sfse-version", "Safeshare-SFSE-Version", true},
		{"safeshare-sfse-version", "Safeshare-Sfse-Version", true},
		{"safeshare-sfse-version", "safeshare-sfse-version", true},
		{"", "", true},
		{"a", "b", false},
		{"abc", "abcd", false},
		{"safeshare-sfse-version", "safeshare-sfse2-enc-file-id", false},
	}
	for _, tc := range cases {
		if got := equalFold(tc.a, tc.b); got != tc.want {
			t.Errorf("equalFold(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestComputeSFSE2CiphertextRange_S3Math exercises the public helper at
// boundaries that matter for S3 Range requests: aligned-to-chunk,
// straddling-chunk, last-chunk-shorter, and empty-file cases. The helper
// itself lives in internal/utils, but this test asserts the values match
// what the s3 wrapper feeds into the GetObject Range header.
func TestComputeSFSE2CiphertextRange_S3Math(t *testing.T) {
	const chunkSize = int64(4)
	// 10-byte plaintext = 3 chunks: [0..3], [4..7], [8..9] (2 bytes in final).
	const plaintextLen = int64(10)
	header := int64(utils.SFSE2HeaderSize)
	overhead := int64(utils.SFSE2OverheadPerChunk)
	encFullChunk := chunkSize + overhead
	encFinalChunk := int64(2) + overhead

	tests := []struct {
		name              string
		pStart, pEnd      int64
		wantCTStart       int64
		wantCTEnd         int64
	}{
		{
			name:        "full read",
			pStart:      0,
			pEnd:        plaintextLen - 1,
			wantCTStart: header,
			wantCTEnd:   header + 2*encFullChunk + encFinalChunk - 1,
		},
		{
			name:        "first chunk only (0..3)",
			pStart:      0,
			pEnd:        3,
			wantCTStart: header,
			wantCTEnd:   header + encFullChunk - 1,
		},
		{
			name:        "middle chunk only (4..7)",
			pStart:      4,
			pEnd:        7,
			wantCTStart: header + encFullChunk,
			wantCTEnd:   header + 2*encFullChunk - 1,
		},
		{
			name:        "last chunk only (8..9)",
			pStart:      8,
			pEnd:        9,
			wantCTStart: header + 2*encFullChunk,
			wantCTEnd:   header + 2*encFullChunk + encFinalChunk - 1,
		},
		{
			name:        "straddle 0..7",
			pStart:      2,
			pEnd:        5,
			wantCTStart: header,
			wantCTEnd:   header + 2*encFullChunk - 1,
		},
		{
			name:        "straddle last + clamp pEnd above totalPlaintextLen",
			pStart:      6,
			pEnd:        100, // clamps to plaintextLen-1 = 9
			wantCTStart: header + encFullChunk,
			wantCTEnd:   header + 2*encFullChunk + encFinalChunk - 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctStart, ctEnd, err := utils.ComputeSFSE2CiphertextRange(tt.pStart, tt.pEnd, chunkSize, plaintextLen)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ctStart != tt.wantCTStart || ctEnd != tt.wantCTEnd {
				t.Errorf("got ctStart=%d ctEnd=%d, want ctStart=%d ctEnd=%d",
					ctStart, ctEnd, tt.wantCTStart, tt.wantCTEnd)
			}
		})
	}
}

// TestComputeSFSE2CiphertextRange_Rejections checks the error paths.
func TestComputeSFSE2CiphertextRange_Rejections(t *testing.T) {
	cases := []struct {
		name                            string
		pStart, pEnd, chunkSize, plLen int64
	}{
		{"negative chunkSize", 0, 0, -1, 10},
		{"zero chunkSize", 0, 0, 0, 10},
		{"negative plaintextLen", 0, 0, 4, -1},
		{"plaintextStart > plaintextEnd", 5, 4, 4, 10},
		{"plaintextStart beyond total", 100, 200, 4, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := utils.ComputeSFSE2CiphertextRange(tc.pStart, tc.pEnd, tc.chunkSize, tc.plLen)
			if err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

// TestS3MetadataValueRoundTrip asserts the strconv.FormatInt / hex.Encode
// values we put into S3 UserMetadata round-trip cleanly through ParseInt /
// hex.Decode in parseSFSE2Metadata. Catches bugs where someone changes the
// formatter on one side but not the other.
func TestS3MetadataValueRoundTrip(t *testing.T) {
	id := make([]byte, utils.SFSE2EncFileIDSize)
	for i := range id {
		id[i] = byte(0xA0 + i)
	}
	for _, plen := range []int64{0, 1, 1023, 1 << 30, 1<<63 - 1} {
		t.Run(strconv.FormatInt(plen, 10), func(t *testing.T) {
			meta := map[string]string{
				s3MetaSFSEVersion:       "2",
				s3MetaSFSE2EncFileID:    hex.EncodeToString(id),
				s3MetaSFSE2PlaintextLen: strconv.FormatInt(plen, 10),
			}
			gotID, gotLen, ok := parseSFSE2Metadata(meta)
			if !ok {
				t.Fatalf("parseSFSE2Metadata failed for plen=%d", plen)
			}
			if hex.EncodeToString(gotID) != hex.EncodeToString(id) {
				t.Errorf("enc_file_id round-trip mismatch")
			}
			if gotLen != plen {
				t.Errorf("plaintext_len round-trip: got %d, want %d", gotLen, plen)
			}
		})
	}
}
