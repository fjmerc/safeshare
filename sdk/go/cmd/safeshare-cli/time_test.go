package main

import (
	"strings"
	"testing"
	"time"
)

// inZone runs the test with the local time zone set to a fixed one.
func inZone(t *testing.T, name string, offset int) {
	t.Helper()
	old := time.Local
	time.Local = time.FixedZone(name, offset)
	t.Cleanup(func() { time.Local = old })
}

func TestFormatTimeShowsLocalTimeAndZone(t *testing.T) {
	inZone(t, "CET", 3600)
	got := formatTime(time.Date(2026, 11, 10, 6, 14, 3, 0, time.UTC))
	if want := "2026-11-10 07:14:03 CET"; got != want {
		t.Fatalf("formatTime = %q, want %q", got, want)
	}
}

func TestUploadBundleShowsLocalExpiry(t *testing.T) {
	inZone(t, "CET", 3600)
	_, srv := newCLIBundleFake(t)
	a := writeTemp(t, "a.txt", "aaa")
	out, _, err := runCLI(t, "--url", srv.URL, "upload", "--bundle", "--no-progress", a)
	if err != nil {
		t.Fatal(err)
	}
	// The fake server says 2030-01-01T00:00:00Z.
	if !strings.Contains(out, "Expires:     2030-01-01 01:00:00 CET\n") {
		t.Fatalf("want the expiry in local time with its zone:\n%s", out)
	}
}

func TestListBundlesShowsLocalTimes(t *testing.T) {
	inZone(t, "CET", 3600)
	_, srv := newCLIBundleFake(t)
	out, _, err := runCLI(t, "--url", srv.URL, "--token", "safeshare_test", "list", "--bundles")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2030-01-01 01:00:00 CET", "2030-01-02 01:00:00 CET"} {
		if !strings.Contains(out, want) {
			t.Fatalf("want %q in:\n%s", want, out)
		}
	}
}
