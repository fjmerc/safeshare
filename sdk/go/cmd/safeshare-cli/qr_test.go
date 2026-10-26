package main

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"

	"rsc.io/qr"
)

// readQR turns printQR's output back into rows of modules (true = light).
func readQR(t *testing.T, out string) [][]bool {
	t.Helper()
	var rows [][]bool
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var top, bottom []bool
		for _, r := range line {
			switch r {
			case '█':
				top, bottom = append(top, true), append(bottom, true)
			case '▀':
				top, bottom = append(top, true), append(bottom, false)
			case '▄':
				top, bottom = append(top, false), append(bottom, true)
			case ' ':
				top, bottom = append(top, false), append(bottom, false)
			default:
				t.Fatalf("unexpected %q in QR output", r)
			}
		}
		rows = append(rows, top, bottom)
	}
	return rows
}

func TestPrintQR(t *testing.T) {
	const link = "https://share.example.com/#/claim/Xk3pQ9aBcD/key/UlAHKlA54ujVH5J7T7bQO1qrPihxGXYNZWGtaXdRpi4"
	var out bytes.Buffer
	if err := printQR(&out, link); err != nil {
		t.Fatal(err)
	}
	code, err := qr.Encode(link, qr.L)
	if err != nil {
		t.Fatal(err)
	}
	n := code.Size + 2*qrQuietZone
	rows := readQR(t, out.String())
	if len(rows) != n+1 { // n is odd: the last line's bottom half is blank
		t.Fatalf("%d rows of modules, want %d", len(rows), n+1)
	}
	for y := 0; y < n; y++ {
		if len(rows[y]) != n {
			t.Fatalf("row %d has %d modules, want %d", y, len(rows[y]), n)
		}
		for x := 0; x < n; x++ {
			inCode := x >= qrQuietZone && y >= qrQuietZone && x < n-qrQuietZone && y < n-qrQuietZone
			want := !inCode || !code.Black(x-qrQuietZone, y-qrQuietZone)
			if rows[y][x] != want {
				t.Fatalf("module (%d,%d) light=%v, want %v", x, y, rows[y][x], want)
			}
		}
	}
}

func TestUploadQR(t *testing.T) {
	var uploads atomic.Int32
	srv := fakeServer(t, &uploads)
	file := writeTemp(t, "a.txt", "hello")

	if _, err := runCLI(t, "--url", srv.URL, "--json", "upload", "--qr", file); err == nil || !strings.Contains(err.Error(), "--qr") {
		t.Errorf("--qr with --json: %v", err)
	}
	if uploads.Load() != 0 {
		t.Fatal("uploaded despite the bad flags")
	}

	out, err := runCLI(t, "--url", srv.URL, "upload", "--no-progress", "--qr", file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, srv.URL+"/claim/code0001") || !strings.Contains(out, "█") {
		t.Errorf("no link or QR code:\n%s", out)
	}
}
