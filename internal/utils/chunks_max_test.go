package utils

import (
	"math"
	"testing"
)

func TestMaxChunksForFileSize(t *testing.T) {
	const (
		MiB = int64(1024 * 1024)
		GiB = 1024 * MiB
	)
	tests := []struct {
		name    string
		maxSize int64
		want    int64
	}{
		{"zero", 0, 0},
		{"negative", -1, 0},
		{"one byte", 1, 1},
		{"one small chunk", 5 * MiB, 1},
		{"one byte over a small chunk", 5*MiB + 1, 2},
		{"just under the 100 MiB band edge", 100*MiB - 1, 20},
		{"at the 100 MiB band edge", 100 * MiB, 20},
		{"one byte over the 100 MiB band edge", 100*MiB + 1, 20},
		{"300 MiB", 300 * MiB, 30},
		{"just under the 1 GiB band edge", GiB - 1, 103},
		// A 1 GiB file is 52 chunks, but a file one byte smaller is 103.
		{"at the 1 GiB band edge", GiB, 103},
		{"one byte over the 1 GiB band edge", GiB + 1, 103},
		{"2.5 GiB", 5 * GiB / 2, 128},
		{"15 GiB", 15 * GiB, 768},
		{"capped at the per-upload maximum", 1024 * GiB, MaxChunksPerUpload},
		// size+chunk-1 used to overflow here and report 103.
		{"largest int64 is capped, not wrapped", math.MaxInt64, MaxChunksPerUpload},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MaxChunksForFileSize(tt.maxSize); got != tt.want {
				t.Errorf("MaxChunksForFileSize(%d) = %d, want %d", tt.maxSize, got, tt.want)
			}
		})
	}
}

// Every file the maximum allows must fit within the reported number of
// chunks: a sweep in 1 MiB steps, plus each band edge one byte either side.
func TestMaxChunksForFileSize_CoversEveryAllowedSize(t *testing.T) {
	const MiB = int64(1024 * 1024)
	edges := []int64{smallFileLimit - 1, smallFileLimit, smallFileLimit + 1,
		mediumFileLimit - 1, mediumFileLimit, mediumFileLimit + 1}
	maxSizes := append([]int64{1, 5 * MiB, 3 * mediumFileLimit, 15 * mediumFileLimit}, edges...)
	for _, maxSize := range maxSizes {
		most := MaxChunksForFileSize(maxSize)
		sizes := append([]int64{1, maxSize, maxSize - 1}, edges...)
		for size := MiB; size <= maxSize; size += MiB {
			sizes = append(sizes, size)
		}
		attained := false
		for _, size := range sizes {
			if size <= 0 || size > maxSize {
				continue
			}
			chunk := CalculateOptimalChunkSize(size)
			need := (size + chunk - 1) / chunk
			if need > most {
				t.Errorf("maxSize %d: a %d-byte file needs %d chunks, more than MaxChunksForFileSize's %d", maxSize, size, need, most)
			}
			if need == most {
				attained = true
			}
		}
		// The bound is tight: some allowed size needs exactly that many.
		if !attained {
			t.Errorf("maxSize %d: no allowed size needs %d chunks; the bound is loose", maxSize, most)
		}
	}
}
