package utils

import (
	"testing"
	"time"
)

// TestResolveReservationTTL_Default — unset env returns the documented default.
func TestResolveReservationTTL_Default(t *testing.T) {
	t.Setenv(reservationTTLEnvVar, "")
	got := ResolveReservationTTL()
	if got != DefaultReservationTTL {
		t.Errorf("default TTL = %s, want %s", got, DefaultReservationTTL)
	}
}

// TestResolveReservationTTL_Parsing — valid duration values are honoured.
func TestResolveReservationTTL_Parsing(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"45m", 45 * time.Minute},
		{"2h", 2 * time.Hour},
		{"1m", minReservationTTL},
		{"24h", maxReservationTTL},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			t.Setenv(reservationTTLEnvVar, c.raw)
			got := ResolveReservationTTL()
			if got != c.want {
				t.Errorf("ResolveReservationTTL(%q) = %s, want %s", c.raw, got, c.want)
			}
		})
	}
}

// TestResolveReservationTTL_RejectsInvalid — unparseable values fall back to the default.
func TestResolveReservationTTL_RejectsInvalid(t *testing.T) {
	t.Setenv(reservationTTLEnvVar, "not-a-duration")
	got := ResolveReservationTTL()
	if got != DefaultReservationTTL {
		t.Errorf("unparseable TTL = %s, want default %s", got, DefaultReservationTTL)
	}
}

// TestResolveReservationTTL_RejectsOutOfRange — too short and too long both clamp to default.
func TestResolveReservationTTL_RejectsOutOfRange(t *testing.T) {
	cases := []string{"30s", "59s", "25h", "8760h"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(reservationTTLEnvVar, raw)
			got := ResolveReservationTTL()
			if got != DefaultReservationTTL {
				t.Errorf("out-of-range %q: got %s, want default %s", raw, got, DefaultReservationTTL)
			}
		})
	}
}
