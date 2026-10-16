package claimcode

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	tests := []struct {
		code string
		want bool
	}{
		{strings.Repeat("a", 7), false},
		{strings.Repeat("a", 8), true},
		{strings.Repeat("a", 32), true},
		{strings.Repeat("a", 33), false},
		{"", false},
		{"abcDEF12-_xyz", true},
		{"abc def12", false},
		{"abc.def12", false},
		{"abc/def12", false},
		{"abcdef1\n", false},
		{"abcdef12\n", false},
	}
	for _, tt := range tests {
		if got := Valid(tt.code); got != tt.want {
			t.Errorf("Valid(%q) = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestShortPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantCode string
		wantOK   bool
	}{
		{"valid 16", "/Xy9kLm8pQz4vDwE_", "Xy9kLm8pQz4vDwE_", true},
		{"valid min", "/abcdefgh", "abcdefgh", true},
		{"valid max", "/" + strings.Repeat("A", 32), strings.Repeat("A", 32), true},
		{"root", "/", "", false},
		{"empty", "", "", false},
		{"no leading slash", "abcdefgh", "", false},
		{"too short", "/abcdefg", "", false},
		{"too long", "/" + strings.Repeat("A", 33), "", false},
		{"bad chars", "/abcdef!!", "", false},
		{"dotted file", "/service-worker.js", "", false},
		{"nested", "/abcdefgh/ijklmnop", "", false},
		{"trailing slash", "/abcdefgh/", "", false},
		{"api claim", "/api/claim/abcdefgh", "", false},
		{"reserved dashboard", "/dashboard", "", false},
		{"reserved assets", "/assets", "", false},
		{"case differs from reserved", "/Dashboard", "Dashboard", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, ok := ShortPath(tt.path)
			if ok != tt.wantOK || code != tt.wantCode {
				t.Errorf("ShortPath(%q) = (%q, %v), want (%q, %v)", tt.path, code, ok, tt.wantCode, tt.wantOK)
			}
		})
	}
}

func TestParseLengthAndValidLength(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"16", 16, false}, {" 8 ", 8, false}, {"32", 32, false},
		{"7", 0, true}, {"33", 0, true}, {"0", 0, true}, {"-1", 0, true},
		{"abc", 0, true}, {"", 0, true}, {"12.5", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseLength(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseLength(%q) = %d, %v; want %d, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
		if err == nil && !ValidLength(got) {
			t.Errorf("ValidLength(%d) = false for parsed value", got)
		}
	}
	if ValidLength(MinLength-1) || ValidLength(MaxLength+1) || !ValidLength(MinLength) || !ValidLength(MaxLength) {
		t.Error("ValidLength boundaries wrong")
	}
}

func TestMask(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "***"}, {"abcde", "***"}, {"abcdef", "a..."}, {"abcdefgh", "a..."},
		{"abcdefghijk", "a..."}, {"abcdefghijkl", "ab..."}, {"abcdefghijklmno", "ab..."},
		{"abcdefghijklmnop", "abc...op"}, {"abcdefghijklmnopqrstuvwxyz012345", "abc...45"},
	}
	for _, tt := range tests {
		if got := Mask(tt.in); got != tt.want {
			t.Errorf("Mask(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLooseShortPath(t *testing.T) {
	for _, p := range []string{"/abcdefgh", "//abcdefgh", "/abcdefgh/", "abcdefgh"} {
		if code, ok := LooseShortPath(p); !ok || code != "abcdefgh" {
			t.Errorf("LooseShortPath(%q) = %q, %v", p, code, ok)
		}
	}
	for _, p := range []string{"/dashboard", "/dashboard/", "/abcdefgh/ijklmnop", "/", "", "/abc"} {
		if _, ok := LooseShortPath(p); ok {
			t.Errorf("LooseShortPath(%q) matched", p)
		}
	}
}
