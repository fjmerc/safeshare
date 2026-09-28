package utils

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestContentDisposition(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "plain ascii",
			in:   "report.pdf",
			want: `attachment; filename="report.pdf"; filename*=UTF-8''report.pdf`,
		},
		{
			name: "space and parens",
			in:   "final report (v2).pdf",
			want: `attachment; filename="final report (v2).pdf"; filename*=UTF-8''final%20report%20%28v2%29.pdf`,
		},
		{
			name: "quote and backslash escaped in ascii fallback",
			in:   `weird"name\here.txt`,
			want: `attachment; filename="weird\"name\\here.txt"; filename*=UTF-8''weird%22name%5Chere.txt`,
		},
		{
			name: "utf-8 non-ascii replaced with underscore in fallback",
			in:   "résumé—final.docx",
			want: `attachment; filename="r_sum__final.docx"; filename*=UTF-8''r%C3%A9sum%C3%A9%E2%80%94final.docx`,
		},
		{
			name: "control characters dropped from both filename and ext-value",
			in:   "bad\tname\x00.txt",
			want: `attachment; filename="badname.txt"; filename*=UTF-8''badname.txt`,
		},
		{
			name: "japanese filename",
			in:   "契約書.pdf",
			want: `attachment; filename="___.pdf"; filename*=UTF-8''%E5%A5%91%E7%B4%84%E6%9B%B8.pdf`,
		},
		{
			name: "empty name falls back to download",
			in:   "",
			want: `attachment; filename="download"; filename*=UTF-8''download`,
		},
		{
			// The RTL-override extension-spoofing trick: a naive renderer
			// would show "invoice‮fdp.exe" as "invoice...exe.pdf".
			// U+202E is category Cf and must be dropped entirely, not
			// merely percent-encoded (percent-encoding it would still let
			// a client that decodes filename* render the override).
			name: "right-to-left override stripped",
			in:   "invoice‮fdp.exe",
			want: `attachment; filename="invoicefdp.exe"; filename*=UTF-8''invoicefdp.exe`,
		},
		{
			name: "left-to-right mark stripped",
			in:   "name‎with-mark.txt",
			want: `attachment; filename="namewith-mark.txt"; filename*=UTF-8''namewith-mark.txt`,
		},
		{
			name: "directional isolates stripped",
			in:   "a⁦b⁧c⁨d⁩e.txt",
			want: `attachment; filename="abcde.txt"; filename*=UTF-8''abcde.txt`,
		},
		{
			name: "line separator stripped",
			in:   "line break.txt",
			want: `attachment; filename="linebreak.txt"; filename*=UTF-8''linebreak.txt`,
		},
		{
			name: "paragraph separator stripped",
			in:   "para graph.txt",
			want: `attachment; filename="paragraph.txt"; filename*=UTF-8''paragraph.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContentDisposition(tt.in)
			if got != tt.want {
				t.Fatalf("ContentDisposition(%q) =\n  %q\nwant\n  %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestContentDisposition_InvalidUTF8(t *testing.T) {
	// Invalid UTF-8 bytes must not survive into either the filename or the
	// filename* ext-value — they're replaced with U+FFFD and then dropped,
	// same as any other disallowed rune.
	in := "bad\xff\xfename.txt"
	got := ContentDisposition(in)
	want := `attachment; filename="badname.txt"; filename*=UTF-8''badname.txt`
	if got != want {
		t.Fatalf("ContentDisposition(%q) =\n  %q\nwant\n  %q", in, got, want)
	}
}

func TestContentDisposition_EmptyAfterSanitize(t *testing.T) {
	// A name consisting entirely of characters that get stripped must fall
	// back to "download", not an empty filename.
	in := "‮‎⁦⁩  \x00\x01"
	got := ContentDisposition(in)
	want := `attachment; filename="download"; filename*=UTF-8''download`
	if got != want {
		t.Fatalf("ContentDisposition(%q) =\n  %q\nwant\n  %q", in, got, want)
	}
}

func TestContentDisposition_LongNameIsCapped(t *testing.T) {
	long := strings.Repeat("a", 400) + ".txt"
	got := ContentDisposition(long)

	if len(got) > 2000 {
		t.Fatalf("ContentDisposition output unexpectedly large: %d bytes", len(got))
	}
	if !strings.Contains(got, ".txt") {
		t.Fatalf("expected the short extension to survive truncation: %q", got)
	}
	if strings.Contains(got, strings.Repeat("a", 400)) {
		t.Fatalf("expected the base name to be truncated, but the full 400-byte run survived: %q", got)
	}

	// The sanitized name itself (not the whole header value) must respect
	// the byte cap.
	sanitized := sanitizeFilename(long)
	if len(sanitized) > maxContentDispositionNameBytes {
		t.Fatalf("sanitizeFilename produced %d bytes, want <= %d", len(sanitized), maxContentDispositionNameBytes)
	}
	if !strings.HasSuffix(sanitized, ".txt") {
		t.Fatalf("sanitizeFilename should preserve the short extension: %q", sanitized)
	}
}

func TestContentDisposition_LongNameNoExtensionIsCapped(t *testing.T) {
	long := strings.Repeat("b", 400)
	sanitized := sanitizeFilename(long)
	if len(sanitized) != maxContentDispositionNameBytes {
		t.Fatalf("sanitizeFilename(no-extension) = %d bytes, want exactly %d", len(sanitized), maxContentDispositionNameBytes)
	}
}

func TestSanitizeFilename_MultibyteRuneNotSplitByCap(t *testing.T) {
	// 300 3-byte runes (900 bytes) with no short extension — the cap must
	// land on a rune boundary, so the result must still be valid UTF-8.
	long := strings.Repeat("契", 300)
	got := sanitizeFilename(long)
	if !utf8.ValidString(got) {
		t.Fatalf("sanitizeFilename produced invalid UTF-8: %q", got)
	}
	if len(got) > maxContentDispositionNameBytes {
		t.Fatalf("sanitizeFilename produced %d bytes, want <= %d", len(got), maxContentDispositionNameBytes)
	}
}
