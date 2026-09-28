package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newRangeRequest(t *testing.T, rangeHeader, ifRange string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	if ifRange != "" {
		req.Header.Set("If-Range", ifRange)
	}
	return req
}

func TestResolveRange_NoRangeHeader(t *testing.T) {
	req := newRangeRequest(t, "", "")
	got := ResolveRange(req, 1000, `"etag"`, time.Now())
	if got.Kind != RangeFull {
		t.Fatalf("Kind = %v, want RangeFull", got.Kind)
	}
}

func TestResolveRange_Table(t *testing.T) {
	const size = 2048

	tests := []struct {
		name        string
		rangeHeader string
		wantKind    RangeKind
		wantStart   int64
		wantEnd     int64
	}{
		{"basic", "bytes=0-1023", RangePartial, 0, 1023},
		{"open-ended", "bytes=1024-", RangePartial, 1024, size - 1},
		{"suffix", "bytes=-500", RangePartial, size - 500, size - 1},
		{"suffix larger than file clamps to whole file", "bytes=-99999", RangePartial, 0, size - 1},
		{"clamp end beyond size", "bytes=1024-999999", RangePartial, 1024, size - 1},
		{"single byte", "bytes=0-0", RangePartial, 0, 0},
		{"last byte", "bytes=2047-2047", RangePartial, size - 1, size - 1},
		{"case-insensitive unit", "BYTES=0-1023", RangePartial, 0, 1023},
		{"mixed-case unit", "ByTeS=0-1023", RangePartial, 0, 1023},

		// Full (ignore Range) cases.
		{"missing bytes prefix", "0-1023", RangeFull, 0, 0},
		{"wrong unit", "items=0-1023", RangeFull, 0, 0},
		{"no hyphen", "bytes=1023", RangeFull, 0, 0},
		{"empty spec", "bytes=-", RangeFull, 0, 0},
		{"start greater than end (explicit)", "bytes=2000-1000", RangeFull, 0, 0},
		{"non-numeric start", "bytes=abc-1023", RangeFull, 0, 0},
		{"non-numeric end", "bytes=0-xyz", RangeFull, 0, 0},
		{"multiple ranges", "bytes=0-100,200-300", RangeFull, 0, 0},
		{"multiple ranges with suffix", "bytes=0-100,-500", RangeFull, 0, 0},
		{"negative start syntax", "bytes=--100-200", RangeFull, 0, 0},

		// Unsatisfiable cases.
		{"start beyond size", "bytes=5000-6000", RangeUnsatisfiable, 0, 0},
		{"start equal to size", "bytes=2048-2100", RangeUnsatisfiable, 0, 0},
		{"zero suffix length", "bytes=-0", RangeUnsatisfiable, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRangeRequest(t, tt.rangeHeader, "")
			got := ResolveRange(req, size, `"etag"`, time.Now())
			if got.Kind != tt.wantKind {
				t.Fatalf("Kind = %v, want %v", got.Kind, tt.wantKind)
			}
			if tt.wantKind == RangePartial {
				if got.Start != tt.wantStart || got.End != tt.wantEnd {
					t.Fatalf("range = [%d,%d], want [%d,%d]", got.Start, got.End, tt.wantStart, tt.wantEnd)
				}
			}
		})
	}
}

func TestResolveRange_ZeroByteFile(t *testing.T) {
	tests := []string{"bytes=0-0", "bytes=0-", "bytes=-1", "bytes=-0"}
	for _, rh := range tests {
		t.Run(rh, func(t *testing.T) {
			req := newRangeRequest(t, rh, "")
			got := ResolveRange(req, 0, `"etag"`, time.Now())
			if got.Kind != RangeUnsatisfiable {
				t.Fatalf("Kind = %v, want RangeUnsatisfiable for %q against a 0-byte file", got.Kind, rh)
			}
		})
	}
}

func TestResolveRange_IfRange(t *testing.T) {
	modTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	const strongETag = `"abc123"`
	const weakETag = `W/"abc123"`
	const size = 1000

	tests := []struct {
		name     string
		ifRange  string
		etag     string
		modTime  time.Time
		wantKind RangeKind
	}{
		{"strong etag match", strongETag, strongETag, modTime, RangePartial},
		{"strong etag mismatch", `"other"`, strongETag, modTime, RangeFull},
		{"weak if-range value never matches", weakETag, weakETag, modTime, RangeFull},
		{"resource etag is weak so if-range etag never matches", strongETag, weakETag, modTime, RangeFull},
		{"date match (second precision)", modTime.Format(http.TimeFormat), strongETag, modTime, RangePartial},
		{"date match ignoring sub-second", modTime.Format(http.TimeFormat), strongETag, modTime.Add(400 * time.Millisecond), RangePartial},
		{"date mismatch", modTime.Add(time.Hour).Format(http.TimeFormat), strongETag, modTime, RangeFull},
		{"unparsable if-range value", "not-a-date-or-etag", strongETag, modTime, RangeFull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRangeRequest(t, "bytes=0-99", tt.ifRange)
			got := ResolveRange(req, size, tt.etag, tt.modTime)
			if got.Kind != tt.wantKind {
				t.Fatalf("Kind = %v, want %v", got.Kind, tt.wantKind)
			}
			if tt.wantKind == RangePartial && (got.Start != 0 || got.End != 99) {
				t.Fatalf("range = [%d,%d], want [0,99]", got.Start, got.End)
			}
		})
	}
}

// TestResolveRange_IfRangeNeverMatchesZeroModTime covers the guard against
// a coincidental match on a zero/epoch modTime: a resource with no real
// last-modified value must never satisfy an If-Range date, even one that
// literally spells out the Unix epoch.
func TestResolveRange_IfRangeNeverMatchesZeroModTime(t *testing.T) {
	epochDate := time.Unix(0, 0).UTC().Format(http.TimeFormat)

	tests := []struct {
		name    string
		modTime time.Time
	}{
		{"zero value Time{}", time.Time{}},
		{"non-zero Time with Unix()==0", time.Unix(0, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRangeRequest(t, "bytes=0-99", epochDate)
			got := ResolveRange(req, 1000, `"etag"`, tt.modTime)
			if got.Kind != RangeFull {
				t.Fatalf("Kind = %v, want RangeFull (a zero/epoch modTime must never satisfy If-Range)", got.Kind)
			}
		})
	}
}

func TestCanonicalRangeHeader(t *testing.T) {
	got := CanonicalRangeHeader(RangeDecision{Kind: RangePartial, Start: 10, End: 99})
	if want := "bytes=10-99"; got != want {
		t.Fatalf("CanonicalRangeHeader() = %q, want %q", got, want)
	}
}
