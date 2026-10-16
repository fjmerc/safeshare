package privacy

import (
	"testing"
	"time"
)

func TestRoundDownToHour(t *testing.T) {
	est := time.FixedZone("est", -5*3600)
	ist := time.FixedZone("ist", 5*3600+1800)
	tests := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{"mid hour", time.Date(2026, 10, 16, 14, 37, 12, 999, time.UTC), time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)},
		{"on boundary", time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC), time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)},
		{"last second", time.Date(2026, 10, 16, 23, 59, 59, 0, time.UTC), time.Date(2026, 10, 16, 23, 0, 0, 0, time.UTC)},
		{"non-UTC zone normalised", time.Date(2026, 10, 16, 9, 41, 0, 0, est), time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)},
		{"half-hour zone normalised", time.Date(2026, 10, 16, 20, 10, 0, 0, ist), time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RoundDownToHour(tt.in)
			if !got.Equal(tt.want) || got.Location() != time.UTC {
				t.Errorf("RoundDownToHour(%v) = %v, want %v (UTC)", tt.in, got, tt.want)
			}
		})
	}
}

func TestRoundUpToHour(t *testing.T) {
	tests := []struct {
		name string
		in   time.Time
		want time.Time
	}{
		{"mid hour", time.Date(2026, 10, 16, 14, 1, 0, 0, time.UTC), time.Date(2026, 10, 16, 15, 0, 0, 0, time.UTC)},
		{"one nanosecond past", time.Date(2026, 10, 16, 14, 0, 0, 1, time.UTC), time.Date(2026, 10, 16, 15, 0, 0, 0, time.UTC)},
		{"on boundary unchanged", time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC), time.Date(2026, 10, 16, 14, 0, 0, 0, time.UTC)},
		{"day rollover", time.Date(2026, 10, 16, 23, 30, 0, 0, time.UTC), time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)},
		{"never-expire sentinel untouched", time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RoundUpToHour(tt.in)
			if !got.Equal(tt.want) {
				t.Errorf("RoundUpToHour(%v) = %v, want %v", tt.in, got, tt.want)
			}
			if got.Before(tt.in) {
				t.Errorf("RoundUpToHour(%v) = %v shortened the time", tt.in, got)
			}
		})
	}
}

// Property: rounding up never shortens and extends by strictly less than an
// hour, for every minute/second offset in a day.
func TestRoundUpToHour_NeverShortensBoundedExtension(t *testing.T) {
	base := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	for s := 0; s < 24*3600; s += 7 {
		in := base.Add(time.Duration(s)*time.Second + 123*time.Millisecond)
		got := RoundUpToHour(in)
		if got.Before(in) || got.Sub(in) >= time.Hour {
			t.Fatalf("in=%v got=%v: extension %v out of [0,1h)", in, got, got.Sub(in))
		}
	}
}
