package privacy

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- JPEG test helpers ---

// buildJPEG constructs a minimal valid JPEG with optional APP1 segment.
func buildJPEG(includeAPP1 bool) []byte {
	var buf bytes.Buffer
	// SOI
	buf.Write([]byte{0xFF, 0xD8})

	// APP0 (JFIF) — keep this
	app0Data := []byte("JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
	buf.Write([]byte{0xFF, 0xE0})
	binary.Write(&buf, binary.BigEndian, uint16(len(app0Data)+2))
	buf.Write(app0Data)

	if includeAPP1 {
		// APP1 (EXIF) — should be stripped
		exifData := []byte("Exif\x00\x00" + "fake EXIF GPS data here 1234567890")
		buf.Write([]byte{0xFF, 0xE1})
		binary.Write(&buf, binary.BigEndian, uint16(len(exifData)+2))
		buf.Write(exifData)
	}

	// DQT (minimal quantization table marker)
	dqtData := make([]byte, 65) // 1 byte precision/id + 64 bytes table
	buf.Write([]byte{0xFF, 0xDB})
	binary.Write(&buf, binary.BigEndian, uint16(len(dqtData)+2))
	buf.Write(dqtData)

	// SOF0 (Start of Frame)
	sof0Data := []byte{
		0x08,                  // precision
		0x00, 0x01,            // height = 1
		0x00, 0x01,            // width = 1
		0x01,                  // num components
		0x01, 0x11, 0x00,     // component 1
	}
	buf.Write([]byte{0xFF, 0xC0})
	binary.Write(&buf, binary.BigEndian, uint16(len(sof0Data)+2))
	buf.Write(sof0Data)

	// SOS + minimal scan data
	sosData := []byte{
		0x01,             // num components
		0x01, 0x00,       // component selector, dc/ac table
		0x00, 0x3F, 0x00, // spectral selection, successive approx
	}
	buf.Write([]byte{0xFF, 0xDA})
	binary.Write(&buf, binary.BigEndian, uint16(len(sosData)+2))
	buf.Write(sosData)

	// Minimal image data
	buf.Write([]byte{0x00})

	// EOI
	buf.Write([]byte{0xFF, 0xD9})

	return buf.Bytes()
}

// buildJPEGWithMultipleAPP1 constructs a JPEG with two APP1 segments.
func buildJPEGWithMultipleAPP1() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI

	// First APP1 (EXIF)
	exif1 := []byte("Exif\x00\x00GPS-DATA-12345")
	buf.Write([]byte{0xFF, 0xE1})
	binary.Write(&buf, binary.BigEndian, uint16(len(exif1)+2))
	buf.Write(exif1)

	// Second APP1 (XMP)
	xmp := []byte("http://ns.adobe.com/xap/1.0/\x00<xmp>data</xmp>")
	buf.Write([]byte{0xFF, 0xE1})
	binary.Write(&buf, binary.BigEndian, uint16(len(xmp)+2))
	buf.Write(xmp)

	// SOS + data + EOI
	buf.Write([]byte{0xFF, 0xDA})
	sosData := []byte{0x01, 0x01, 0x00, 0x00, 0x3F, 0x00}
	binary.Write(&buf, binary.BigEndian, uint16(len(sosData)+2))
	buf.Write(sosData)
	buf.Write([]byte{0x00})
	buf.Write([]byte{0xFF, 0xD9})

	return buf.Bytes()
}

// buildJPEGWithIPTCAndComment constructs a JPEG with APP13 (IPTC) and COM segments.
func buildJPEGWithIPTCAndComment() []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI

	// APP0 (JFIF) — should be kept
	app0Data := []byte("JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
	buf.Write([]byte{0xFF, 0xE0})
	binary.Write(&buf, binary.BigEndian, uint16(len(app0Data)+2))
	buf.Write(app0Data)

	// APP13 (IPTC/Photoshop) — should be stripped
	iptcData := []byte("Photoshop 3.0\x00author=JohnDoe")
	buf.Write([]byte{0xFF, 0xED})
	binary.Write(&buf, binary.BigEndian, uint16(len(iptcData)+2))
	buf.Write(iptcData)

	// COM (Comment) — should be stripped
	comData := []byte("Created with SecretCamera v1.2.3")
	buf.Write([]byte{0xFF, 0xFE})
	binary.Write(&buf, binary.BigEndian, uint16(len(comData)+2))
	buf.Write(comData)

	// SOS + data + EOI
	buf.Write([]byte{0xFF, 0xDA})
	sosData := []byte{0x01, 0x01, 0x00, 0x00, 0x3F, 0x00}
	binary.Write(&buf, binary.BigEndian, uint16(len(sosData)+2))
	buf.Write(sosData)
	buf.Write([]byte{0x00})
	buf.Write([]byte{0xFF, 0xD9})

	return buf.Bytes()
}

// --- PNG test helpers ---

// buildPNGChunk creates a raw PNG chunk (length + type + data + CRC).
func buildPNGChunk(chunkType string, data []byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(data)))
	buf.WriteString(chunkType)
	buf.Write(data)
	// CRC covers type + data
	crc := crc32.ChecksumIEEE(append([]byte(chunkType), data...))
	binary.Write(&buf, binary.BigEndian, crc)
	return buf.Bytes()
}

// buildPNG constructs a minimal valid PNG with optional text chunks.
func buildPNG(includeText bool) []byte {
	var buf bytes.Buffer
	buf.Write(pngSignature)

	// IHDR (required, 13 bytes)
	ihdrData := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdrData[0:4], 1) // width
	binary.BigEndian.PutUint32(ihdrData[4:8], 1) // height
	ihdrData[8] = 8                               // bit depth
	ihdrData[9] = 2                               // color type (RGB)
	buf.Write(buildPNGChunk("IHDR", ihdrData))

	if includeText {
		// tEXt chunk: "Author\x00TestUser"
		buf.Write(buildPNGChunk("tEXt", []byte("Author\x00TestUser")))
		// iTXt chunk
		buf.Write(buildPNGChunk("iTXt", []byte("Comment\x00\x00\x00\x00\x00Test comment")))
		// zTXt chunk (keyword + null + compression method + compressed data)
		buf.Write(buildPNGChunk("zTXt", []byte("Software\x00\x00fake-compressed")))
	}

	// IDAT (minimal image data)
	buf.Write(buildPNGChunk("IDAT", []byte{0x08, 0xD7, 0x63, 0xF8, 0x0F, 0x00, 0x00, 0x01, 0x01, 0x00, 0x05}))

	// IEND
	buf.Write(buildPNGChunk("IEND", nil))

	return buf.Bytes()
}

// buildPNGWithEXIF constructs a PNG with an eXIf chunk.
func buildPNGWithEXIF() []byte {
	var buf bytes.Buffer
	buf.Write(pngSignature)

	ihdrData := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdrData[0:4], 1)
	binary.BigEndian.PutUint32(ihdrData[4:8], 1)
	ihdrData[8] = 8
	ihdrData[9] = 2
	buf.Write(buildPNGChunk("IHDR", ihdrData))

	// eXIf chunk with fake EXIF data
	buf.Write(buildPNGChunk("eXIf", []byte("MM\x00\x2A\x00\x00\x00\x08fake-exif")))

	buf.Write(buildPNGChunk("IDAT", []byte{0x08, 0xD7, 0x63, 0xF8, 0x0F, 0x00, 0x00, 0x01, 0x01, 0x00, 0x05}))
	buf.Write(buildPNGChunk("IEND", nil))

	return buf.Bytes()
}

// buildPNGWithTIME constructs a PNG with a tIME chunk.
func buildPNGWithTIME() []byte {
	var buf bytes.Buffer
	buf.Write(pngSignature)

	ihdrData := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdrData[0:4], 1)
	binary.BigEndian.PutUint32(ihdrData[4:8], 1)
	ihdrData[8] = 8
	ihdrData[9] = 2
	buf.Write(buildPNGChunk("IHDR", ihdrData))

	// tIME chunk: year(2) + month(1) + day(1) + hour(1) + minute(1) + second(1) = 7 bytes
	timeData := []byte{0x07, 0xEA, 0x03, 0x12, 0x0A, 0x1E, 0x00} // 2026-03-18 10:30:00
	buf.Write(buildPNGChunk("tIME", timeData))

	buf.Write(buildPNGChunk("IDAT", []byte{0x08, 0xD7, 0x63, 0xF8, 0x0F, 0x00, 0x00, 0x01, 0x01, 0x00, 0x05}))
	buf.Write(buildPNGChunk("IEND", nil))

	return buf.Bytes()
}

// --- Tests ---

func TestSupportsMetadataStripping(t *testing.T) {
	tests := []struct {
		mimeType string
		expected bool
	}{
		{"image/jpeg", true},
		{"image/png", true},
		{"image/tiff", false},
		{"application/pdf", false},
		{"text/plain", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.mimeType, func(t *testing.T) {
			got := SupportsMetadataStripping(tt.mimeType)
			if got != tt.expected {
				t.Errorf("SupportsMetadataStripping(%q) = %v, want %v", tt.mimeType, got, tt.expected)
			}
		})
	}
}

func TestStripFileMetadata_UnsupportedType(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(f, []byte("hello world"), 0644)

	err := StripFileMetadata(f, "text/plain")
	if err != nil {
		t.Errorf("expected nil for unsupported type, got %v", err)
	}
}

func TestStripFileMetadata_NonExistentFile(t *testing.T) {
	err := StripFileMetadata("/nonexistent/path/file.jpg", "image/jpeg")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestStripFileMetadata_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "empty.jpg")
	os.WriteFile(f, []byte{}, 0644)

	err := StripFileMetadata(f, "image/jpeg")
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestStripJPEGMetadata_WithEXIF(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.jpg")

	original := buildJPEG(true)
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "image/jpeg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)
	if len(stripped) >= len(original) {
		t.Errorf("expected file to shrink after stripping, original=%d stripped=%d", len(original), len(stripped))
	}

	// Verify no APP1 markers remain
	if containsMarker(stripped, 0xE1) {
		t.Error("stripped file still contains APP1 marker")
	}

	// Verify SOI and EOI are intact
	if stripped[0] != 0xFF || stripped[1] != 0xD8 {
		t.Error("SOI marker missing after stripping")
	}
	if stripped[len(stripped)-2] != 0xFF || stripped[len(stripped)-1] != 0xD9 {
		t.Error("EOI marker missing after stripping")
	}

	// Verify APP0 (JFIF) is preserved
	if !containsMarker(stripped, 0xE0) {
		t.Error("APP0 (JFIF) marker should be preserved")
	}
}

func TestStripJPEGMetadata_WithoutEXIF(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.jpg")

	original := buildJPEG(false)
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "image/jpeg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after, _ := os.ReadFile(f)
	if !bytes.Equal(original, after) {
		t.Error("file should be unchanged when no metadata present")
	}
}

func TestStripJPEGMetadata_MultipleAPP1(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.jpg")

	original := buildJPEGWithMultipleAPP1()
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "image/jpeg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)
	if containsMarker(stripped, 0xE1) {
		t.Error("stripped file still contains APP1 marker(s)")
	}
	if len(stripped) >= len(original) {
		t.Errorf("expected file to shrink, original=%d stripped=%d", len(original), len(stripped))
	}
}

func TestStripJPEGMetadata_IPTCAndComment(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.jpg")

	original := buildJPEGWithIPTCAndComment()
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "image/jpeg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)

	// Verify APP13 (IPTC) is stripped
	if containsMarker(stripped, 0xED) {
		t.Error("stripped file still contains APP13 (IPTC) marker")
	}

	// Verify COM is stripped
	if containsMarker(stripped, markerCOM) {
		t.Error("stripped file still contains COM marker")
	}

	// Verify APP0 (JFIF) is preserved
	if !containsMarker(stripped, 0xE0) {
		t.Error("APP0 (JFIF) marker should be preserved")
	}

	if len(stripped) >= len(original) {
		t.Errorf("expected file to shrink, original=%d stripped=%d", len(original), len(stripped))
	}
}

func TestStripJPEGMetadata_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "bad.jpg")
	os.WriteFile(f, []byte("not a jpeg file"), 0644)

	err := StripFileMetadata(f, "image/jpeg")
	if err == nil {
		t.Error("expected error for invalid JPEG")
	}
}

func TestStripJPEGMetadata_PreservesPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.jpg")

	original := buildJPEG(true)
	os.WriteFile(f, original, 0600)

	err := StripFileMetadata(f, "image/jpeg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, _ := os.Stat(f)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestStripPNGMetadata_WithTextChunks(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.png")

	original := buildPNG(true)
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "image/png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)
	if len(stripped) >= len(original) {
		t.Errorf("expected file to shrink after stripping, original=%d stripped=%d", len(original), len(stripped))
	}

	// Verify no text chunks remain
	if containsPNGChunk(stripped, "tEXt") || containsPNGChunk(stripped, "iTXt") || containsPNGChunk(stripped, "zTXt") {
		t.Error("stripped file still contains text metadata chunks")
	}

	// Verify required chunks are intact
	if !containsPNGChunk(stripped, "IHDR") {
		t.Error("IHDR chunk missing after stripping")
	}
	if !containsPNGChunk(stripped, "IDAT") {
		t.Error("IDAT chunk missing after stripping")
	}
	if !containsPNGChunk(stripped, "IEND") {
		t.Error("IEND chunk missing after stripping")
	}
}

func TestStripPNGMetadata_WithoutTextChunks(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.png")

	original := buildPNG(false)
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "image/png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	after, _ := os.ReadFile(f)
	if !bytes.Equal(original, after) {
		t.Error("file should be unchanged when no text chunks present")
	}
}

func TestStripPNGMetadata_WithEXIFChunk(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.png")

	original := buildPNGWithEXIF()
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "image/png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)
	if containsPNGChunk(stripped, "eXIf") {
		t.Error("stripped file still contains eXIf chunk")
	}
}

func TestStripPNGMetadata_WithTIMEChunk(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.png")

	original := buildPNGWithTIME()
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "image/png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)
	if containsPNGChunk(stripped, "tIME") {
		t.Error("stripped file still contains tIME chunk")
	}
	if len(stripped) >= len(original) {
		t.Errorf("expected file to shrink, original=%d stripped=%d", len(original), len(stripped))
	}
}

func TestStripPNGMetadata_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "bad.png")
	os.WriteFile(f, []byte("not a png file at all"), 0644)

	err := StripFileMetadata(f, "image/png")
	if err == nil {
		t.Error("expected error for invalid PNG")
	}
}

func TestStripPNGMetadata_PreservesPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.png")

	original := buildPNG(true)
	os.WriteFile(f, original, 0600)

	err := StripFileMetadata(f, "image/png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, _ := os.Stat(f)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}
}

// --- Office document test helpers ---

// buildOfficeDoc creates a minimal Office Open XML file (DOCX/XLSX/PPTX are all ZIP-based).
// If includeDocProps is true, includes core.xml and app.xml with identifying metadata.
func buildOfficeDoc(t *testing.T, includeDocProps bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// [Content_Types].xml (required)
	ct := contentTypes{
		XMLName: xml.Name{Space: nsContentTypes, Local: "Types"},
		Defaults: []contentDefault{
			{Extension: "rels", ContentType: "application/vnd.openxmlformats-package.relationships+xml"},
			{Extension: "xml", ContentType: "application/xml"},
		},
		Overrides: []contentOverride{
			{PartName: "/word/document.xml", ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"},
		},
	}
	if includeDocProps {
		ct.Overrides = append(ct.Overrides,
			contentOverride{PartName: "/docProps/core.xml", ContentType: "application/vnd.openxmlformats-package.core-properties+xml"},
			contentOverride{PartName: "/docProps/app.xml", ContentType: "application/vnd.openxmlformats-officedocument.extended-properties+xml"},
		)
	}
	ctData, _ := xml.MarshalIndent(ct, "", "  ")
	ctData = append([]byte(xml.Header), ctData...)
	writeZipEntry(t, w, "[Content_Types].xml", ctData)

	// _rels/.rels (required)
	rels := relationships{
		XMLName: xml.Name{Space: nsRelationships, Local: "Relationships"},
		Rels: []relationship{
			{ID: "rId1", Type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument", Target: "word/document.xml"},
		},
	}
	if includeDocProps {
		rels.Rels = append(rels.Rels,
			relationship{ID: "rId2", Type: "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", Target: "docProps/core.xml"},
			relationship{ID: "rId3", Type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties", Target: "docProps/app.xml"},
		)
	}
	relsData, _ := xml.MarshalIndent(rels, "", "  ")
	relsData = append([]byte(xml.Header), relsData...)
	writeZipEntry(t, w, "_rels/.rels", relsData)

	// word/document.xml (minimal document body)
	docBody := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Hello World</w:t></w:r></w:p></w:body>
</w:document>`
	writeZipEntry(t, w, "word/document.xml", []byte(docBody))

	if includeDocProps {
		// docProps/core.xml — Dublin Core metadata with identifying info
		coreXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/">
  <dc:creator>John Doe Whistleblower</dc:creator>
  <cp:lastModifiedBy>John Doe</cp:lastModifiedBy>
  <dcterms:created>2026-03-18T10:00:00Z</dcterms:created>
  <dcterms:modified>2026-03-18T12:00:00Z</dcterms:modified>
  <cp:revision>5</cp:revision>
</cp:coreProperties>`
		writeZipEntry(t, w, "docProps/core.xml", []byte(coreXML))

		// docProps/app.xml — Application metadata
		appXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <AppVersion>16.0000</AppVersion>
  <Company>Secret Organization Inc.</Company>
  <Template>Normal.dotm</Template>
  <TotalTime>42</TotalTime>
</Properties>`
		writeZipEntry(t, w, "docProps/app.xml", []byte(appXML))
	}

	w.Close()
	return buf.Bytes()
}

func writeZipEntry(t *testing.T, w *zip.Writer, name string, data []byte) {
	t.Helper()
	f, err := w.Create(name)
	if err != nil {
		t.Fatalf("failed to create ZIP entry %s: %v", name, err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("failed to write ZIP entry %s: %v", name, err)
	}
}

// zipContainsEntry checks if a ZIP file contains an entry with the given name prefix.
func zipContainsEntry(data []byte, prefix string) bool {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, f := range r.File {
		if strings.HasPrefix(f.Name, prefix) {
			return true
		}
	}
	return false
}

// zipEntryContent reads the content of a ZIP entry.
func zipEntryContent(t *testing.T, data []byte, name string) []byte {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("failed to open ZIP: %v", err)
	}
	for _, f := range r.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("failed to open entry %s: %v", name, err)
			}
			defer rc.Close()
			content, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("failed to read entry %s: %v", name, err)
			}
			return content
		}
	}
	return nil
}

// --- Office document tests ---

func TestSupportsMetadataStripping_OfficeFormats(t *testing.T) {
	tests := []struct {
		mimeType string
		expected bool
	}{
		{"application/vnd.openxmlformats-officedocument.wordprocessingml.document", true},
		{"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", true},
		{"application/vnd.openxmlformats-officedocument.presentationml.presentation", true},
		{"application/msword", false},           // Legacy .doc not supported
		{"application/vnd.ms-excel", false},      // Legacy .xls not supported
	}

	for _, tt := range tests {
		t.Run(tt.mimeType, func(t *testing.T) {
			got := SupportsMetadataStripping(tt.mimeType)
			if got != tt.expected {
				t.Errorf("SupportsMetadataStripping(%q) = %v, want %v", tt.mimeType, got, tt.expected)
			}
		})
	}
}

func TestStripOfficeMetadata_WithDocProps(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.docx")

	original := buildOfficeDoc(t, true)
	os.WriteFile(f, original, 0644)

	// Verify docProps exist before stripping
	if !zipContainsEntry(original, "docProps/") {
		t.Fatal("test file should contain docProps before stripping")
	}

	err := StripFileMetadata(f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)

	// Verify docProps are gone
	if zipContainsEntry(stripped, "docProps/") {
		t.Error("stripped file still contains docProps entries")
	}

	// Verify document content is preserved
	docContent := zipEntryContent(t, stripped, "word/document.xml")
	if docContent == nil {
		t.Fatal("word/document.xml missing after stripping")
	}
	if !strings.Contains(string(docContent), "Hello World") {
		t.Error("document content was corrupted")
	}

	// Verify [Content_Types].xml no longer references docProps
	ctContent := zipEntryContent(t, stripped, "[Content_Types].xml")
	if strings.Contains(string(ctContent), "docProps") {
		t.Error("[Content_Types].xml still references docProps")
	}

	// Verify _rels/.rels no longer references docProps
	relsContent := zipEntryContent(t, stripped, "_rels/.rels")
	if strings.Contains(string(relsContent), "docProps") {
		t.Error("_rels/.rels still references docProps")
	}

	// Verify the officeDocument relationship is preserved
	if !strings.Contains(string(relsContent), "word/document.xml") {
		t.Error("_rels/.rels lost the officeDocument relationship")
	}
}

func TestStripOfficeMetadata_WithoutDocProps(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.docx")

	original := buildOfficeDoc(t, false)
	os.WriteFile(f, original, 0644)

	err := StripFileMetadata(f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File should be unchanged (no docProps to strip)
	after, _ := os.ReadFile(f)
	if !bytes.Equal(original, after) {
		t.Error("file should be unchanged when no docProps present")
	}
}

func TestStripOfficeMetadata_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "bad.docx")
	os.WriteFile(f, []byte("not a zip file"), 0644)

	err := StripFileMetadata(f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err == nil {
		t.Error("expected error for invalid file")
	}
}

func TestStripOfficeMetadata_PreservesPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.docx")

	original := buildOfficeDoc(t, true)
	os.WriteFile(f, original, 0600)

	err := StripFileMetadata(f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, _ := os.Stat(f)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestStripOfficeMetadata_AllFormats(t *testing.T) {
	mimeTypes := []struct {
		mime string
		ext  string
	}{
		{"application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx"},
		{"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"},
		{"application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx"},
	}

	for _, mt := range mimeTypes {
		t.Run(mt.ext, func(t *testing.T) {
			tmpDir := t.TempDir()
			f := filepath.Join(tmpDir, "test"+mt.ext)

			original := buildOfficeDoc(t, true)
			os.WriteFile(f, original, 0644)

			err := StripFileMetadata(f, mt.mime)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", mt.ext, err)
			}

			stripped, _ := os.ReadFile(f)
			if zipContainsEntry(stripped, "docProps/") {
				t.Errorf("%s: docProps still present after stripping", mt.ext)
			}
		})
	}
}

func TestStripOfficeMetadata_CustomXml(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.docx")

	// Build a doc with customXml/ directory
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Minimal structural files
	ct := contentTypes{
		XMLName:  xml.Name{Space: nsContentTypes, Local: "Types"},
		Defaults: []contentDefault{{Extension: "xml", ContentType: "application/xml"}},
		Overrides: []contentOverride{
			{PartName: "/word/document.xml", ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"},
			{PartName: "/customXml/item1.xml", ContentType: "application/xml"},
		},
	}
	ctData, _ := xml.MarshalIndent(ct, "", "  ")
	writeZipEntry(t, w, "[Content_Types].xml", ctData)

	rels := relationships{
		XMLName: xml.Name{Space: nsRelationships, Local: "Relationships"},
		Rels: []relationship{
			{ID: "rId1", Type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument", Target: "word/document.xml"},
			{ID: "rId4", Type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml", Target: "customXml/item1.xml"},
		},
	}
	relsData, _ := xml.MarshalIndent(rels, "", "  ")
	writeZipEntry(t, w, "_rels/.rels", relsData)
	writeZipEntry(t, w, "word/document.xml", []byte("<doc>content</doc>"))
	writeZipEntry(t, w, "customXml/item1.xml", []byte("<tracking>secret-id-12345</tracking>"))
	w.Close()

	os.WriteFile(f, buf.Bytes(), 0644)

	err := StripFileMetadata(f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)
	if zipContainsEntry(stripped, "customXml/") {
		t.Error("customXml/ should be stripped")
	}

	// Verify structural references are also cleaned
	ctContent := zipEntryContent(t, stripped, "[Content_Types].xml")
	if strings.Contains(string(ctContent), "customXml") {
		t.Error("[Content_Types].xml still references customXml")
	}
}

func TestStripOfficeMetadata_LeadingSlashTarget(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "test.docx")

	// Build a doc where _rels/.rels uses absolute pack URIs (leading slash)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	ct := contentTypes{
		XMLName:  xml.Name{Space: nsContentTypes, Local: "Types"},
		Defaults: []contentDefault{{Extension: "xml", ContentType: "application/xml"}},
		Overrides: []contentOverride{
			{PartName: "/word/document.xml", ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"},
			{PartName: "/docProps/core.xml", ContentType: "application/vnd.openxmlformats-package.core-properties+xml"},
		},
	}
	ctData, _ := xml.MarshalIndent(ct, "", "  ")
	writeZipEntry(t, w, "[Content_Types].xml", ctData)

	// Note: Target uses leading slash (absolute pack URI)
	rels := relationships{
		XMLName: xml.Name{Space: nsRelationships, Local: "Relationships"},
		Rels: []relationship{
			{ID: "rId1", Type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument", Target: "word/document.xml"},
			{ID: "rId2", Type: "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", Target: "/docProps/core.xml"},
		},
	}
	relsData, _ := xml.MarshalIndent(rels, "", "  ")
	writeZipEntry(t, w, "_rels/.rels", relsData)
	writeZipEntry(t, w, "word/document.xml", []byte("<doc>content</doc>"))
	writeZipEntry(t, w, "docProps/core.xml", []byte("<props><author>Secret Agent</author></props>"))
	w.Close()

	os.WriteFile(f, buf.Bytes(), 0644)

	err := StripFileMetadata(f, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stripped, _ := os.ReadFile(f)

	// Verify docProps removed
	if zipContainsEntry(stripped, "docProps/") {
		t.Error("docProps/ should be stripped")
	}

	// Verify _rels/.rels no longer references docProps (even with leading slash)
	relsContent := zipEntryContent(t, stripped, "_rels/.rels")
	if strings.Contains(string(relsContent), "docProps") {
		t.Error("_rels/.rels still references docProps (leading-slash target not handled)")
	}
}

// --- Test helpers ---

// containsMarker checks if a JPEG byte stream contains a specific marker.
// Note: This is a simple scanner that looks for 0xFF followed by the marker byte.
// It may produce false positives in image scan data, but is sufficient for our
// synthetic test fixtures which have minimal scan data.
func containsMarker(data []byte, marker byte) bool {
	for i := 2; i < len(data)-1; i++ { // Skip SOI
		if data[i] == 0xFF && data[i+1] == marker {
			return true
		}
	}
	return false
}

func containsPNGChunk(data []byte, chunkType string) bool {
	ct := []byte(chunkType)
	// Search after the 8-byte PNG signature
	for i := 8; i < len(data)-7; {
		if len(data) < i+8 {
			break
		}
		chunkLen := binary.BigEndian.Uint32(data[i : i+4])
		if bytes.Equal(data[i+4:i+8], ct) {
			return true
		}
		i += int(12 + chunkLen) // 4 len + 4 type + data + 4 CRC
	}
	return false
}
