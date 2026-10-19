package privacy

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
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

// Entries the cleaner doesn't change are copied still compressed: a part
// that inflates past the old 500 MB budget no longer gets inflated at all.
func TestStripOfficeBytes_CopiesUnchangedPartsCompressed(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeZipEntry(t, zw, "[Content_Types].xml", []byte(`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`))
	writeZipEntry(t, zw, "_rels/.rels", []byte(`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`))
	writeZipEntry(t, zw, "docProps/core.xml", []byte(`<cp:coreProperties><dc:creator>Jane Source</dc:creator></cp:coreProperties>`))
	big, err := zw.CreateHeader(&zip.FileHeader{Name: "word/media/huge.bin", Method: zip.Deflate, Modified: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	const hugeSize = maxDecompressedSize + 20<<20
	zeros := make([]byte, 1<<20)
	for written := 0; written < hugeSize; written += len(zeros) {
		if _, err := big.Write(zeros); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	out, stripped, err := stripOfficeBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("stripOfficeBytes: %v", err)
	}
	if !stripped || zipContainsEntry(out, "docProps/") || bytes.Contains(out, []byte("Jane Source")) {
		t.Fatal("docProps not removed")
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if !f.Modified.Equal(officeEntryTime) {
			t.Errorf("%s keeps its time %v", f.Name, f.Modified)
		}
		if f.Name == "word/media/huge.bin" {
			if f.UncompressedSize64 != hugeSize {
				t.Errorf("huge entry size = %d", f.UncompressedSize64)
			}
			// Reading it back checks the copied data against its CRC.
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			n, err := io.Copy(io.Discard, rc)
			rc.Close()
			if err != nil || n != hugeSize {
				t.Errorf("reading huge entry: %d bytes, %v", n, err)
			}
		}
	}
}

// A real Word document still reads entry by entry after cleaning.
func TestStripOfficeBytes_RealDocument(t *testing.T) {
	data, err := os.ReadFile("../../tests/js/fixtures/sample.docx")
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	out, err := StripMetadataBytes(data, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "docProps/") {
			t.Errorf("%s left in", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if _, err := io.Copy(io.Discard, rc); err != nil {
			t.Errorf("%s: %v", f.Name, err)
		}
		rc.Close()
	}
}

// overlappingZip builds a zip whose central directory lists the same
// stored entry copies times: every record points at the one local entry.
func overlappingZip(t *testing.T, entrySize, copies int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: "word/media/big.bin", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte{'A'}, entrySize)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	eocd := bytes.LastIndex(data, []byte("PK\x05\x06"))
	cdSize := int(binary.LittleEndian.Uint32(data[eocd+12:]))
	cdOff := int(binary.LittleEndian.Uint32(data[eocd+16:]))
	record := data[cdOff : cdOff+cdSize]

	var out bytes.Buffer
	out.Write(data[:cdOff])
	for i := 0; i < copies; i++ {
		out.Write(record)
	}
	end := append([]byte(nil), data[eocd:eocd+22]...)
	binary.LittleEndian.PutUint16(end[8:], uint16(copies))
	binary.LittleEndian.PutUint16(end[10:], uint16(copies))
	binary.LittleEndian.PutUint32(end[12:], uint32(cdSize*copies))
	out.Write(end)
	return out.Bytes()
}

func TestStripOfficeBytes_RefusesOverlappingEntries(t *testing.T) {
	data := overlappingZip(t, 1<<20, 300)
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil || len(zr.File) != 300 {
		t.Fatalf("fixture: %v files, %v", len(zr.File), err)
	}
	out, _, err := stripOfficeBytes(data)
	if err == nil {
		t.Fatalf("accepted; output %d bytes from a %d-byte file", len(out), len(data))
	}
}

func TestStripOfficeBytes_RefusesTooManyEntries(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i <= maxOfficeEntries; i++ {
		if _, err := zw.Create(fmt.Sprintf("word/p%d.xml", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stripOfficeBytes(buf.Bytes()); err == nil {
		t.Error("accepted a file with too many parts")
	}
}

func TestStripOfficeBytes_CleansEmbeddedPhotos(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeZipEntry(t, zw, "[Content_Types].xml", []byte(`<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`))
	writeZipEntry(t, zw, "word/document.xml", []byte("<w:document/>"))
	writeZipEntry(t, zw, "word/media/image1.jpeg", buildJPEG(true))
	writeZipEntry(t, zw, "ppt/media/image2.png", buildPNGWithEXIF())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	out, _, err := stripOfficeBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	jpg := zipEntryContent(t, out, "word/media/image1.jpeg")
	if containsMarker(jpg, 0xE1) {
		t.Error("embedded JPEG keeps its APP1 (EXIF) segment")
	}
	if png := zipEntryContent(t, out, "ppt/media/image2.png"); containsPNGChunk(png, "eXIf") {
		t.Error("embedded PNG keeps its eXIf chunk")
	}
	if got := zipEntryContent(t, out, "word/document.xml"); string(got) != "<w:document/>" {
		t.Errorf("document part changed: %q", got)
	}

	// Photos are recognised by content, not by name or folder.
	var hidden bytes.Buffer
	zw = zip.NewWriter(&hidden)
	writeZipEntry(t, zw, "customUI/images/logo.bin", buildJPEG(true))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if out, _, err = stripOfficeBytes(hidden.Bytes()); err != nil {
		t.Fatal(err)
	}
	if containsMarker(zipEntryContent(t, out, "customUI/images/logo.bin"), 0xE1) {
		t.Error("a JPEG outside media/ keeps its EXIF")
	}

	// Photo formats that hold EXIF but can't be cleaned stop the file.
	for name, head := range map[string][]byte{
		"word/media/a.tiff": []byte("II*\x00rest-of-tiff"),
		"word/media/a.wdp":  []byte("II\xbc\x01rest"),
		"word/media/a.heic": append([]byte{0, 0, 0, 24}, []byte("ftypheic....")...),
	} {
		var b bytes.Buffer
		zw = zip.NewWriter(&b)
		writeZipEntry(t, zw, name, head)
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stripOfficeBytes(b.Bytes()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A broken embedded photo stops the whole file rather than passing
	// through uncleaned.
	var bad bytes.Buffer
	zw = zip.NewWriter(&bad)
	// Starts like a JPEG, then an APP1 segment longer than the file.
	writeZipEntry(t, zw, "word/media/image1.jpeg", []byte{0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xF0, 'E', 'x', 'i', 'f'})
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stripOfficeBytes(bad.Bytes()); err == nil {
		t.Error("accepted a broken embedded photo")
	}
}

// buildPDF assembles objects (numbered from 1, object 1 the catalog) into a
// PDF with a correct cross-reference table.
func buildPDF(objects []string) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return buf.Bytes()
}

func TestStripPDFBytes_PageMetadataAndAnnotationAuthors(t *testing.T) {
	xmp := "<x:xmpmeta>PAGEXMPSECRET</x:xmpmeta>"
	data := buildPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Metadata 4 0 R /Annots [5 0 R] /PieceInfo << /App << /Private (PIECEINFOSECRET) >> >> >>",
		fmt.Sprintf("<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n%s\nendstream", len(xmp), xmp),
		"<< /Type /Annot /Subtype /Text /Rect [10 10 50 50] /Contents (a note) /T (ANNOTAUTHORSECRET) /M (D:20260101120000Z) /CreationDate (D:20260101120000Z) /NM (ANNOTIDSECRET) >>",
	})
	out, err := StripMetadataBytes(data, "application/pdf")
	if err != nil {
		t.Fatal(err)
	}
	// pdfcpu packs objects into compressed object streams on write, so look
	// at the parsed objects, not the raw bytes.
	all := pdfObjectsText(t, out)
	for _, needle := range []string{"PAGEXMPSECRET", "PIECEINFOSECRET", "ANNOTAUTHORSECRET", "ANNOTIDSECRET", "D:20260101120000Z"} {
		if strings.Contains(all, needle) {
			t.Errorf("%s survived", needle)
		}
	}
	if !strings.Contains(all, "a note") {
		t.Error("the annotation's text was removed; only its author and dates should go")
	}
}

func TestStripPDFBytes_RefusesTooManyObjects(t *testing.T) {
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [] /Count 0 >>"}
	for len(objects) < maxPDFObjects+10 {
		objects = append(objects, "<< /A 1 >>")
	}
	if _, err := StripMetadataBytes(buildPDF(objects), "application/pdf"); err == nil {
		t.Error("accepted a PDF with too many objects")
	}
}

func TestCheckPDFObjectCount_ObjectStreams(t *testing.T) {
	for name, data := range map[string]string{
		"small":            "1 0 obj << /Type /ObjStm /N 50 /First 10 /Length 3 >> stream\nabc\nendstream endobj",
		"outlines":         "1 0 obj << /Type /Outlines /First 5 0 R /Last 9 0 R /Count 3 >> endobj",
		"outline item":     "5 0 obj << /Title (Chapter 1) /Parent 1 0 R /First 6 0 R /Last 7 0 R /Dest [3 0 R /Fit] >> endobj",
		"tricky title":     "5 0 obj << /Title (a \\) stream \\( (nested) title) /First 6 0 R >> endobj 6 0 obj << /Length 1 >> stream\nx\nendstream endobj",
		"nested dict":      "1 0 obj << /DecodeParms << /Columns 5 >> /Type /ObjStm /N 50 /First 10 >> endobj",
		"/N further along": "1 0 obj << /Type /ObjStm " + strings.Repeat(" ", 2000) + "/N 5 /First 3 >> endobj",
		"/FirstChar font":  "1 0 obj << /Type /Font /FirstChar 32 /LastChar 126 >> endobj",
	} {
		if err := checkPDFObjectCount([]byte(data)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, data := range map[string]string{
		"huge count":            "1 0 obj << /Type /ObjStm /N 900000 /First 10 >> stream\nx\nendstream endobj",
		"indirect /N":           "1 0 obj << /Type /ObjStm /N 7 0 R /First 10 >> stream\nx\nendstream endobj",
		"no /N at all":          "1 0 obj << /Type /ObjStm /First 10 >> stream\nx\nendstream endobj",
		"/N only nested":        "1 0 obj << /Type /ObjStm /First 10 /X << /N 5 >> >> stream\nx\nendstream endobj",
		"two /N":                "1 0 obj << /Type /ObjStm /N 5 /N 900000 /First 10 >> stream\nx\nendstream endobj",
		"escaped name":          "1 0 obj << /Type /Obj#53tm /N 900000 /First 10 >> stream\nx\nendstream endobj",
		"no /Type, /First":      "1 0 obj << /N 900000 /First 10 >> stream\nx\nendstream endobj",
		"no /Type, indirect":    "1 0 obj << /N 7 0 R /First 10 >>\nstream\nx\nendstream endobj",
		"string in dictionary":  "1 0 obj << /Type /ObjStm /X (<<) /N 5 /First 1 >> stream\nx\nendstream endobj",
		"comment hiding /N":     "1 0 obj << /Type /ObjStm /N 900000 %>> /N 5\n /First 1 >> stream\nx\nendstream endobj",
		"comment faking /N":     "1 0 obj << /Type /ObjStm %\n/N 5\n /First 1 >> stream\nx\nendstream endobj",
		"keyword in a name":     "1 0 obj << /Type /ObjStm /Xendobj 1 /N 900000 /First 1 >> stream\nx\nendstream endobj",
		"keyword in hex string": "1 0 obj << /Type /ObjStm /X <656e646f626a> endobjx /N 900000 /First 1 >> stream\nx\nendstream endobj",
		"keyword in a string":   "1 0 obj << /Type /ObjStm /X (endobj) /N 900000 /First 1 >> stream\nx\nendstream endobj",
		"comment before stream": "1 0 obj << /Type /ObjStm /N 900000 /First 1 >> %c\nstream\nx\nendstream endobj",
	} {
		if err := checkPDFObjectCount([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The real sample PDFs used by the browser tests (one with object streams,
// one linearized) still clean.
func TestStripPDFBytes_RealSamples(t *testing.T) {
	for _, name := range []string{"sample.pdf", "sample-objstm.pdf", "sample-linear.pdf"} {
		data, err := os.ReadFile("../../tests/js/fixtures/" + name)
		if err != nil {
			t.Skipf("fixtures not available: %v", err)
		}
		if _, err := StripMetadataBytes(data, "application/pdf"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// pdfObjectsText parses a PDF and returns every object it holds as text,
// stream contents decoded, so tests can search it.
func pdfObjectsText(t *testing.T, data []byte) string {
	t.Helper()
	conf := model.NewStatelessConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	ctx, err := api.ReadContext(context.Background(), bytes.NewReader(data), conf)
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if err := api.ValidateContext(context.Background(), ctx); err != nil {
		t.Fatalf("output doesn't validate: %v", err)
	}
	var sb strings.Builder
	for nr, entry := range ctx.XRefTable.Table {
		if entry == nil || entry.Free || entry.Object == nil {
			continue
		}
		fmt.Fprintf(&sb, "%d: %v\n", nr, entry.Object)
		if sd, ok := entry.Object.(types.StreamDict); ok {
			if err := sd.Decode(); err == nil {
				sb.Write(sd.Content)
				sb.WriteByte('\n')
			}
		}
	}
	return sb.String()
}

// A PDF with a table of contents (an outline tree, which uses /First too)
// still cleans.
func TestStripPDFBytes_WithBookmarks(t *testing.T) {
	data := buildPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R /Outlines 4 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
		"<< /Type /Outlines /First 5 0 R /Last 5 0 R /Count 1 >>",
		"<< /Title (Chapter 1) /Parent 4 0 R /Dest [3 0 R /Fit] >>",
	})
	out, err := StripMetadataBytes(data, "application/pdf")
	if err != nil {
		t.Fatalf("a PDF with bookmarks was refused: %v", err)
	}
	if !strings.Contains(pdfObjectsText(t, out), "Chapter 1") {
		t.Error("bookmark lost")
	}
}

func TestStripOfficeBytes_CleansEmbeddedVideo(t *testing.T) {
	box := func(typ string, payload ...[]byte) []byte {
		body := bytes.Join(payload, nil)
		out := binary.BigEndian.AppendUint32(nil, uint32(8+len(body)))
		return append(append(out, typ...), body...)
	}
	gps := "+40.7128-074.0060/"
	clip := bytes.Join([][]byte{
		box("ftyp", []byte("mp42\x00\x00\x00\x00mp42isom")),
		box("moov", box("mvhd", make([]byte, 100)), box("udta", box("\xa9xyz", []byte{0, byte(len(gps)), 0x15, 0xc7}, []byte(gps)))),
		box("mdat", []byte("frames")),
	}, nil)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	writeZipEntry(t, zw, "ppt/media/media1.mp4", clip)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	out, _, err := stripOfficeBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(zipEntryContent(t, out, "ppt/media/media1.mp4"), []byte(gps)) {
		t.Error("a video in a presentation keeps its location tag")
	}
}
