package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

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

func TestVersion(t *testing.T) {
	old := version
	version = "9.8.7"
	defer func() { version = old }()

	for _, args := range [][]string{{"--version"}, {"version"}} {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetArgs(args)
		cmd.SetOut(&out)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.HasPrefix(out.String(), "safeshare-cli 9.8.7\n") {
			t.Errorf("%v printed %q", args, out.String())
		}
	}

	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetArgs([]string{"version"})
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if want := runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH; !strings.Contains(out.String(), want) {
		t.Errorf("version printed %q, want it to include %q", out.String(), want)
	}
}

// -v stays --verbose, and verify keeps its own --version (a release to check).
func TestVersionFlagsDontClash(t *testing.T) {
	cmd := newRootCmd()
	cmd.InitDefaultVersionFlag() // as Execute does
	if f := cmd.Flags().ShorthandLookup("v"); f == nil || f.Name != "verbose" {
		t.Errorf("-v is %v, want --verbose", f)
	}
	verify, _, err := cmd.Find([]string{"verify"})
	if err != nil {
		t.Fatal(err)
	}
	if f := verify.Flags().Lookup("version"); f == nil || f.Value.Type() != "string" {
		t.Errorf("verify --version is %v, want a string flag", f)
	}
}
