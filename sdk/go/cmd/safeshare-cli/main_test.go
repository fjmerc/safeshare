package main

import "testing"

func TestEscapeControls(t *testing.T) {
	cases := map[string]string{
		"plain error":                  "plain error",
		"line one\nline two":           "line one\nline two",
		"bad \x1b]52;c;ZXZpbA==\x07 x": `bad \x1b]52;c;ZXZpbA==\a x`,
		"rtl \u202etxt.exe":            "rtl \\u202etxt.exe",
	}
	for in, want := range cases {
		if got := escapeControls(in); got != want {
			t.Errorf("escapeControls(%q) = %q, want %q", in, got, want)
		}
	}
	if got := display("evil\x1b[2Jname"); got != `"evil\x1b[2Jname"` {
		t.Errorf("display: %s", got)
	}
}
