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

func TestRedactUsername(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		anonymousMode bool
		want          string
	}{
		{"enabled returns redacted", "alice", true, "redacted"},
		{"disabled returns original", "alice", false, "alice"},
		{"enabled with empty username", "", true, "redacted"},
		{"disabled with empty username", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactUsername(tt.username, tt.anonymousMode); got != tt.want {
				t.Errorf("RedactUsername(%q, %v) = %q, want %q", tt.username, tt.anonymousMode, got, tt.want)
			}
		})
	}
}

func TestAnonymizeAndRedactUserAgentFilenamePath(t *testing.T) {
	const ua = "Mozilla/5.0 (X11; Linux)"
	if got := AnonymizeUserAgent(ua, true); got != "" {
		t.Errorf("AnonymizeUserAgent(anon) = %q, want empty", got)
	}
	if got := AnonymizeUserAgent(ua, false); got != ua {
		t.Errorf("AnonymizeUserAgent(normal) = %q, want %q", got, ua)
	}
	if got := RedactUserAgent(ua, true); got != "redacted" {
		t.Errorf("RedactUserAgent(anon) = %q", got)
	}
	if got := RedactUserAgent(ua, false); got != ua {
		t.Errorf("RedactUserAgent(normal) = %q", got)
	}
	if got := RedactFilename("secret.pdf", true); got != "[redacted]" {
		t.Errorf("RedactFilename(anon) = %q", got)
	}
	if got := RedactFilename("secret.pdf", false); got != "secret.pdf" {
		t.Errorf("RedactFilename(normal) = %q", got)
	}
	tests := []struct {
		path string
		anon bool
		want string
	}{
		{"/api/claim/AbCdEf123456", true, "/api/[redacted]"},
		{"/api/claim/AbCdEf123456", false, "/api/claim/AbCdEf123456"},
		{"/health", true, "/health"},
		{"/", true, "/"},
		{"", true, ""},
		{"/claim/AbCdEf", true, "/claim/[redacted]"},
	}
	for _, tt := range tests {
		if got := RedactPath(tt.path, tt.anon); got != tt.want {
			t.Errorf("RedactPath(%q, %v) = %q, want %q", tt.path, tt.anon, got, tt.want)
		}
	}
}
