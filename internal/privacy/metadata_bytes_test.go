package privacy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The in-memory and file strippers must cover the same types, or a type
// cleaned for normal uploads would silently pass through the drop page
// uncleaned.
func TestStripMetadataBytes_CoversSameTypes(t *testing.T) {
	for mime := range supportedMimeTypes {
		if _, ok := supportedBytesStrippers[mime]; !ok {
			t.Errorf("%s has a file stripper but no in-memory one", mime)
		}
	}
	for mime := range supportedBytesStrippers {
		if _, ok := supportedMimeTypes[mime]; !ok {
			t.Errorf("%s has an in-memory stripper but no file one", mime)
		}
	}
}

// For the deterministic formats, stripping in memory gives exactly what
// stripping the file gives.
func TestStripMetadataBytes_MatchesFileStripper(t *testing.T) {
	cases := []struct {
		name, mime string
		data       []byte
	}{
		{"jpeg exif", "image/jpeg", buildJPEG(true)},
		{"jpeg iptc", "image/jpeg", buildJPEGWithIPTCAndComment()},
		{"png text", "image/png", buildPNG(true)},
		{"png exif", "image/png", buildPNGWithEXIF()},
		{"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", buildOfficeDoc(t, true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := bytes.Clone(tc.data)
			got, err := StripMetadataBytes(input, tc.mime)
			if err != nil {
				t.Fatalf("StripMetadataBytes: %v", err)
			}
			if !bytes.Equal(input, tc.data) {
				t.Fatal("StripMetadataBytes modified its input")
			}

			path := filepath.Join(t.TempDir(), "f")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := StripFileMetadata(path, tc.mime); err != nil {
				t.Fatalf("StripFileMetadata: %v", err)
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(want, tc.data) {
				t.Fatal("fixture has nothing to strip; the comparison would be vacuous")
			}
			if !bytes.Equal(got, want) {
				t.Errorf("in-memory result (%d bytes) differs from file result (%d bytes)", len(got), len(want))
			}
		})
	}
}

func TestStripMetadataBytes_PDF(t *testing.T) {
	data := buildPDFWithMetadata(t)
	input := bytes.Clone(data)

	got, err := StripMetadataBytes(input, "application/pdf")
	if err != nil {
		t.Fatalf("StripMetadataBytes: %v", err)
	}
	if !bytes.Equal(input, data) {
		t.Fatal("StripMetadataBytes modified its input")
	}

	path := filepath.Join(t.TempDir(), "out.pdf")
	if err := os.WriteFile(path, got, 0o600); err != nil {
		t.Fatal(err)
	}
	after := readPDFContext(t, path)
	if info := pdfInfoValues(t, after); len(info) != 0 {
		t.Errorf("Info dict not empty: %v", info)
	}
	if pdfHasCatalogMetadata(t, after) {
		t.Error("catalog /Metadata (XMP) present after stripping")
	}
	if after.PageCount != 1 {
		t.Errorf("PageCount = %d, want 1", after.PageCount)
	}
	needles := []string{pdfFixtureXMPMarker, pdfFixtureID, "pdfcpu"}
	for _, key := range pdfInfoKeys {
		needles = append(needles, pdfFixtureInfo[key])
	}
	for _, needle := range needles {
		if bytes.Contains(bytes.ToUpper(got), bytes.ToUpper([]byte(needle))) {
			t.Errorf("stripped PDF still contains %q", needle)
		}
	}
}

func TestStripMetadataBytes_UnsupportedTypeUnchanged(t *testing.T) {
	data := []byte("just some text")
	got, err := StripMetadataBytes(data, "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if &got[0] != &data[0] || len(got) != len(data) {
		t.Error("unsupported type: want the input returned as it is")
	}
}

func TestStripMetadataBytes_NothingToStripUnchanged(t *testing.T) {
	data := buildJPEG(false)
	got, err := StripMetadataBytes(data, "image/jpeg")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("JPEG without metadata changed")
	}
}

func TestStripMetadataBytes_Errors(t *testing.T) {
	if _, err := StripMetadataBytes(nil, "image/jpeg"); err == nil {
		t.Error("empty input: want an error")
	}
	if _, err := StripMetadataBytes([]byte("not a jpeg"), "image/jpeg"); err == nil {
		t.Error("invalid JPEG: want an error")
	}
	if _, err := StripMetadataBytes([]byte("%PDF-1.4 broken"), "application/pdf"); err == nil {
		t.Error("broken PDF: want an error")
	}
	big := make([]byte, maxStrippableFileSize+1)
	if _, err := StripMetadataBytes(big, "image/jpeg"); !errors.Is(err, ErrFileTooLarge) {
		t.Errorf("oversized input: err = %v, want ErrFileTooLarge", err)
	}
}
