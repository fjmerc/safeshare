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

// TestResolveCompleteGrace_Default — unset env returns the documented default (T42).
func TestResolveCompleteGrace_Default(t *testing.T) {
	t.Setenv(completeGraceEnvVar, "")
	got := ResolveCompleteGrace()
	if got != DefaultCompleteGrace {
		t.Errorf("default complete grace = %s, want %s", got, DefaultCompleteGrace)
	}
}

// TestResolveCompleteGrace_ZeroDisables — an explicit "0" (numeric, or one of
// the documented word spellings) is honoured exactly (not replaced by the
// default): 0 is the documented way to disable the T42 grace window and
// restore pre-T42 behaviour.
func TestResolveCompleteGrace_ZeroDisables(t *testing.T) {
	cases := []string{"0", "0s", "0m", "0h", "off", "OFF", "false", "False", "disabled", "none", "no"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(completeGraceEnvVar, raw)
			got := ResolveCompleteGrace()
			if got != 0 {
				t.Errorf("ResolveCompleteGrace(%q) = %s, want 0 (disabled)", raw, got)
			}
		})
	}
}

// TestResolveCompleteGrace_Parsing — valid, in-range duration values are honoured.
func TestResolveCompleteGrace_Parsing(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
		{"1s", minCompleteGrace},
		{"1h", maxCompleteGrace},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			t.Setenv(completeGraceEnvVar, c.raw)
			got := ResolveCompleteGrace()
			if got != c.want {
				t.Errorf("ResolveCompleteGrace(%q) = %s, want %s", c.raw, got, c.want)
			}
		})
	}
}

// TestResolveCompleteGrace_RejectsInvalid — an unparseable value must fail
// CLOSED (disable the grace window) rather than falling back to the
// (enabled) default — security-audit follow-up: this control widens when a
// session token can still be used, so garbage input must not silently leave
// it enabled.
func TestResolveCompleteGrace_RejectsInvalid(t *testing.T) {
	t.Setenv(completeGraceEnvVar, "not-a-duration")
	got := ResolveCompleteGrace()
	if got != 0 {
		t.Errorf("unparseable complete grace = %s, want 0 (fail closed, not the default)", got)
	}
}

// TestResolveCompleteGrace_NegativeFailsClosed — a negative duration is
// invalid configuration (not a spelling of "disabled"): it must also fail
// closed to 0, not fall back to the enabled default.
func TestResolveCompleteGrace_NegativeFailsClosed(t *testing.T) {
	cases := []string{"-1s", "-5m", "-1h"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Setenv(completeGraceEnvVar, raw)
			got := ResolveCompleteGrace()
			if got != 0 {
				t.Errorf("negative %q: got %s, want 0 (fail closed)", raw, got)
			}
		})
	}
}

// TestResolveCompleteGrace_ClampsOutOfRange — a valid, POSITIVE duration
// outside [minCompleteGrace, maxCompleteGrace] is clamped to the nearer
// bound (the operator's intent to enable it is unambiguous), not replaced by
// the default and not disabled.
func TestResolveCompleteGrace_ClampsOutOfRange(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"500ms", minCompleteGrace}, // below min, nonzero -> clamp up
		{"2h", maxCompleteGrace},    // above max -> clamp down
		{"8760h", maxCompleteGrace},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			t.Setenv(completeGraceEnvVar, c.raw)
			got := ResolveCompleteGrace()
			if got != c.want {
				t.Errorf("out-of-range %q: got %s, want %s (clamped)", c.raw, got, c.want)
			}
		})
	}
}
