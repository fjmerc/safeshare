package privacy

import "testing"

func TestAnonymizeIP(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		anonymousMode bool
		want          string
	}{
		{"enabled returns anonymous", "192.168.1.1", true, "anonymous"},
		{"disabled returns original", "192.168.1.1", false, "192.168.1.1"},
		{"enabled with IPv6", "::1", true, "anonymous"},
		{"disabled with IPv6", "2001:db8::1", false, "2001:db8::1"},
		{"enabled with empty IP", "", true, "anonymous"},
		{"disabled with empty IP", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnonymizeIP(tt.ip, tt.anonymousMode)
			if got != tt.want {
				t.Errorf("AnonymizeIP(%q, %v) = %q, want %q", tt.ip, tt.anonymousMode, got, tt.want)
			}
		})
	}
}

func TestRedactIP(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		anonymousMode bool
		want          string
	}{
		{"enabled returns redacted", "10.0.0.1", true, "redacted"},
		{"disabled returns original", "10.0.0.1", false, "10.0.0.1"},
		{"enabled with IPv6", "::1", true, "redacted"},
		{"disabled with IPv6", "fe80::1", false, "fe80::1"},
		{"enabled with empty IP", "", true, "redacted"},
		{"disabled with empty IP", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactIP(tt.ip, tt.anonymousMode)
			if got != tt.want {
				t.Errorf("RedactIP(%q, %v) = %q, want %q", tt.ip, tt.anonymousMode, got, tt.want)
			}
		})
	}
}
