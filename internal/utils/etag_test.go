package utils

import (
	"testing"
	"time"
)

func TestComputeClaimETag_FormatAndStrength(t *testing.T) {
	now := time.Unix(1735689600, 123456789)
	etag := ComputeClaimETag("abc123.bin", 4096, now)

	if len(etag) != 34 {
		t.Fatalf("ETag length = %d, want 34 (quote + 32 hex + quote), got %q", len(etag), etag)
	}
	if etag[0] != '"' || etag[len(etag)-1] != '"' {
		t.Errorf("ETag = %q, want a quoted strong validator (no W/ prefix)", etag)
	}
	for _, c := range etag[1 : len(etag)-1] {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Fatalf("ETag payload contains non-hex character %q in %q", c, etag)
		}
	}
}

func TestComputeClaimETag_Deterministic(t *testing.T) {
	now := time.Unix(1735689600, 0)
	a := ComputeClaimETag("stored.bin", 100, now)
	b := ComputeClaimETag("stored.bin", 100, now)
	if a != b {
		t.Errorf("ComputeClaimETag is not deterministic: %q != %q", a, b)
	}
}

func TestComputeClaimETag_DiffersOnEachField(t *testing.T) {
	base := time.Unix(1735689600, 0)
	baseline := ComputeClaimETag("a.bin", 100, base)

	cases := []struct {
		name           string
		storedFilename string
		fileSize       int64
		createdAt      time.Time
	}{
		{"filename", "b.bin", 100, base},
		{"size", "a.bin", 200, base},
		{"createdAt", "a.bin", 100, base.Add(time.Second)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeClaimETag(tc.storedFilename, tc.fileSize, tc.createdAt)
			if got == baseline {
				t.Errorf("changing %s did not change the ETag (got %q both times)", tc.name, got)
			}
		})
	}
}
