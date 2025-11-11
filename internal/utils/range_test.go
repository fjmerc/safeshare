package utils

import (
	"testing"
)

func TestParseRange(t *testing.T) {
	tests := []struct {
		name        string
		rangeHeader string
		fileSize    int64
		wantStart   int64
		wantEnd     int64
		wantErr     bool
	}{
		{
			name:        "basic range",
			rangeHeader: "bytes=0-1023",
			fileSize:    2048,
			wantStart:   0,
			wantEnd:     1023,
			wantErr:     false,
		},
		{
			name:        "range from middle",
			rangeHeader: "bytes=1024-2047",
			fileSize:    4096,
			wantStart:   1024,
			wantEnd:     2047,
			wantErr:     false,
		},
		{
			name:        "open-ended range",
			rangeHeader: "bytes=1024-",
			fileSize:    2048,
			wantStart:   1024,
			wantEnd:     2047,
			wantErr:     false,
		},
		{
			name:        "suffix range (last 500 bytes)",
			rangeHeader: "bytes=-500",
			fileSize:    2048,
			wantStart:   1548,
			wantEnd:     2047,
			wantErr:     false,
		},
		{
			name:        "suffix range larger than file",
			rangeHeader: "bytes=-5000",
			fileSize:    2048,
			wantStart:   0,
			wantEnd:     2047,
			wantErr:     false,
		},
		{
			name:        "single byte",
			rangeHeader: "bytes=0-0",
			fileSize:    2048,
			wantStart:   0,
			wantEnd:     0,
			wantErr:     false,
		},
		{
			name:        "last byte",
			rangeHeader: "bytes=2047-2047",
			fileSize:    2048,
			wantStart:   2047,
			wantEnd:     2047,
			wantErr:     false,
		},
		{
			name:        "range beyond file size (clamped)",
			rangeHeader: "bytes=1024-9999",
			fileSize:    2048,
			wantStart:   1024,
			wantEnd:     2047,
			wantErr:     false,
		},
		{
			name:        "entire file",
			rangeHeader: "bytes=0-2047",
			fileSize:    2048,
			wantStart:   0,
			wantEnd:     2047,
			wantErr:     false,
		},
		// Error cases
		{
			name:        "missing bytes prefix",
			rangeHeader: "0-1023",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "invalid format (no hyphen)",
			rangeHeader: "bytes=1023",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "start greater than end",
			rangeHeader: "bytes=2000-1000",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "start beyond file size",
			rangeHeader: "bytes=5000-6000",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "negative start",
			rangeHeader: "bytes=-100-200",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "invalid start (not a number)",
			rangeHeader: "bytes=abc-1023",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "invalid end (not a number)",
			rangeHeader: "bytes=0-xyz",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "empty range",
			rangeHeader: "bytes=-",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "zero suffix length",
			rangeHeader: "bytes=-0",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "multi-range (not supported)",
			rangeHeader: "bytes=0-100,200-300",
			fileSize:    2048,
			wantErr:     true,
		},
		{
			name:        "negative file size",
			rangeHeader: "bytes=0-100",
			fileSize:    -1,
			wantErr:     true,
		},
		{
			name:        "zero file size with range",
			rangeHeader: "bytes=0-0",
			fileSize:    0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ParseRange(tt.rangeHeader, tt.fileSize)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseRange() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseRange() unexpected error: %v", err)
				return
			}

			if r.Start != tt.wantStart {
				t.Errorf("ParseRange() start = %d, want %d", r.Start, tt.wantStart)
			}

			if r.End != tt.wantEnd {
				t.Errorf("ParseRange() end = %d, want %d", r.End, tt.wantEnd)
			}
		})
	}
}

func TestHTTPRange_ContentLength(t *testing.T) {
	tests := []struct {
		name       string
		r          HTTPRange
		wantLength int64
	}{
		{
			name:       "single byte",
			r:          HTTPRange{Start: 0, End: 0},
			wantLength: 1,
		},
		{
			name:       "1024 bytes",
			r:          HTTPRange{Start: 0, End: 1023},
			wantLength: 1024,
		},
		{
			name:       "middle range",
			r:          HTTPRange{Start: 1024, End: 2047},
			wantLength: 1024,
		},
		{
			name:       "large range",
			r:          HTTPRange{Start: 0, End: 1048575},
			wantLength: 1048576, // 1MB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.ContentLength()
			if got != tt.wantLength {
				t.Errorf("HTTPRange.ContentLength() = %d, want %d", got, tt.wantLength)
			}
		})
	}
}

func TestHTTPRange_ContentRangeHeader(t *testing.T) {
	tests := []struct {
		name     string
		r        HTTPRange
		fileSize int64
		want     string
	}{
		{
			name:     "first 1KB",
			r:        HTTPRange{Start: 0, End: 1023},
			fileSize: 2048,
			want:     "bytes 0-1023/2048",
		},
		{
			name:     "last 1KB",
			r:        HTTPRange{Start: 1024, End: 2047},
			fileSize: 2048,
			want:     "bytes 1024-2047/2048",
		},
		{
			name:     "single byte",
			r:        HTTPRange{Start: 0, End: 0},
			fileSize: 1,
			want:     "bytes 0-0/1",
		},
		{
			name:     "large file range",
			r:        HTTPRange{Start: 0, End: 1048575},
			fileSize: 10737418240, // 10GB
			want:     "bytes 0-1048575/10737418240",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.r.ContentRangeHeader(tt.fileSize)
			if got != tt.want {
				t.Errorf("HTTPRange.ContentRangeHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseRange_Whitespace(t *testing.T) {
	tests := []struct {
		name        string
		rangeHeader string
		fileSize    int64
		wantStart   int64
		wantEnd     int64
	}{
		{
			name:        "spaces around range",
			rangeHeader: "bytes= 0-1023 ",
			fileSize:    2048,
			wantStart:   0,
			wantEnd:     1023,
		},
		{
			name:        "spaces around hyphen",
			rangeHeader: "bytes=0 - 1023",
			fileSize:    2048,
			wantStart:   0,
			wantEnd:     1023,
		},
		{
			name:        "tabs and spaces",
			rangeHeader: "bytes=	0	-	1023	",
			fileSize:    2048,
			wantStart:   0,
			wantEnd:     1023,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ParseRange(tt.rangeHeader, tt.fileSize)
			if err != nil {
				t.Errorf("ParseRange() unexpected error: %v", err)
				return
			}

			if r.Start != tt.wantStart || r.End != tt.wantEnd {
				t.Errorf("ParseRange() = {%d, %d}, want {%d, %d}", r.Start, r.End, tt.wantStart, tt.wantEnd)
			}
		})
	}
}
