package privacy

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Directories to strip from Office Open XML files.
const (
	docPropsPrefix  = "docProps/"
	customXMLPrefix = "customXml/"
)

// maxDecompressedSize is the cumulative decompressed size budget for ZIP processing.
// Prevents decompression bomb attacks where a small ZIP expands to gigabytes.
const maxDecompressedSize = 500 * 1024 * 1024 // 500 MB

// maxXMLEntrySize is the maximum size for structural XML entries ([Content_Types].xml, _rels/.rels).
// These files are typically < 10 KB; anything larger is suspicious.
const maxXMLEntrySize = 1 * 1024 * 1024 // 1 MB

// officeXMLHeader matches the XML declaration used by Office applications.
const officeXMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"

// XML namespace constants for Office Open XML structural files.
const (
	nsContentTypes  = "http://schemas.openxmlformats.org/package/2006/content-types"
	nsRelationships = "http://schemas.openxmlformats.org/package/2006/relationships"
)

// contentTypes represents [Content_Types].xml
type contentTypes struct {
	XMLName   xml.Name          `xml:"Types"`
	Defaults  []contentDefault  `xml:"Default"`
	Overrides []contentOverride `xml:"Override"`
}

type contentDefault struct {
	Extension   string `xml:"Extension,attr"`
	ContentType string `xml:"ContentType,attr"`
}

type contentOverride struct {
	PartName    string `xml:"PartName,attr"`
	ContentType string `xml:"ContentType,attr"`
}

// relationships represents _rels/.rels
type relationships struct {
	XMLName xml.Name       `xml:"Relationships"`
	Rels    []relationship `xml:"Relationship"`
}

type relationship struct {
	ID         string `xml:"Id,attr"`
	Type       string `xml:"Type,attr"`
	Target     string `xml:"Target,attr"`
	TargetMode string `xml:"TargetMode,attr,omitempty"`
}

// isMetadataPath returns true if the ZIP entry path should be stripped.
func isMetadataPath(name string) bool {
	return strings.HasPrefix(name, docPropsPrefix) || strings.HasPrefix(name, customXMLPrefix)
}

// stripOfficeMetadata removes metadata from Office Open XML files (DOCX, XLSX, PPTX).
// It removes the docProps/ and customXml/ directories and updates structural references.
//
// Note: This strips file-level metadata (author, company, timestamps, custom properties).
// Document content metadata such as comments, tracked changes, and RSID editing session
// identifiers are NOT stripped as they require modifying document content.
func stripOfficeMetadata(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat Office file: %w", err)
	}
	if info.Size() > maxStrippableFileSize {
		return fmt.Errorf("file too large for metadata stripping: %d bytes (max %d)", info.Size(), maxStrippableFileSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read Office file: %w", err)
	}

	result, stripped, err := stripOfficeBytes(data)
	if err != nil {
		return err
	}
	if !stripped {
		return nil // No metadata to strip
	}

	// Atomic write: temp file then rename to prevent data loss on crash
	tmpPath := filePath + ".strip-tmp"
	if err := os.WriteFile(tmpPath, result, info.Mode().Perm()); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename stripped file: %w", err)
	}
	return nil
}

// stripOfficeBytes is stripOfficeMetadata on an in-memory file. The file is
// always rebuilt, even with no docProps/customXml to drop, because the
// rebuild also clears the entries' save times, extra fields and comments.
func stripOfficeBytes(data []byte) ([]byte, bool, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false, fmt.Errorf("not a valid ZIP/Office file: %w", err)
	}

	result, err := rebuildOfficeZIP(reader)
	if err != nil {
		return nil, false, err
	}
	return result, true, nil
}

// officeEntryTime replaces every entry's modification time in a rebuilt
// file: the original times record when the document was last saved.
var officeEntryTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// rebuildOfficeZIP creates a new ZIP without metadata entries. Entries it
// doesn't change are copied still compressed, so a crafted file can't make
// it inflate more than the two small XML files it filters (each capped at
// maxXMLEntrySize, and all together at maxDecompressedSize). Entry times,
// extra fields and comments are not carried over.
func rebuildOfficeZIP(reader *zip.Reader) ([]byte, error) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)

	var totalDecompressed int64

	for _, f := range reader.File {
		// Skip metadata directories
		if isMetadataPath(f.Name) {
			continue
		}

		// Reject path traversal in ZIP entries (defense in depth)
		cleaned := filepath.ToSlash(f.Name)
		if strings.Contains(cleaned, "..") {
			return nil, fmt.Errorf("invalid ZIP entry name: %s", f.Name)
		}

		var filter func([]byte) ([]byte, error)
		switch f.Name {
		case "[Content_Types].xml":
			filter = filterContentTypes
		case "_rels/.rels":
			filter = filterRelationships
		}

		if filter == nil {
			if err := copyZipEntryRaw(writer, f); err != nil {
				return nil, err
			}
			continue
		}

		// Read entry with decompression size limit
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open ZIP entry %s: %w", f.Name, err)
		}
		limited := io.LimitReader(rc, maxDecompressedSize-totalDecompressed+1)
		entryData, err := io.ReadAll(limited)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read ZIP entry %s: %w", f.Name, err)
		}
		totalDecompressed += int64(len(entryData))
		if totalDecompressed > maxDecompressedSize {
			return nil, fmt.Errorf("ZIP decompressed size exceeds limit (%d bytes)", maxDecompressedSize)
		}

		// Filter structural XML files to remove metadata references
		if entryData, err = filter(entryData); err != nil {
			return nil, fmt.Errorf("failed to filter %s: %w", f.Name, err)
		}

		// Create entry preserving the original compression method
		header := &zip.FileHeader{
			Name:     f.Name,
			Method:   f.Method,
			Modified: officeEntryTime,
			NonUTF8:  f.NonUTF8,
		}
		w, err := writer.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("failed to create ZIP entry %s: %w", f.Name, err)
		}
		if _, err := w.Write(entryData); err != nil {
			return nil, fmt.Errorf("failed to write ZIP entry %s: %w", f.Name, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close ZIP writer: %w", err)
	}

	return buf.Bytes(), nil
}

// copyZipEntryRaw copies f into w without decompressing it, under a fresh
// header that keeps only what reading it needs.
func copyZipEntryRaw(w *zip.Writer, f *zip.File) error {
	if f.Method != zip.Store && f.Method != zip.Deflate {
		return fmt.Errorf("unsupported compression method %d in ZIP entry %s", f.Method, f.Name)
	}
	raw, err := f.OpenRaw()
	if err != nil {
		return fmt.Errorf("failed to open ZIP entry %s: %w", f.Name, err)
	}
	dst, err := w.CreateRaw(&zip.FileHeader{
		Name:   f.Name,
		Method: f.Method,
		// CreateRaw writes the MS-DOS date fields as given (unlike
		// CreateHeader, it doesn't derive them from Modified): 1980-01-01.
		Modified:           officeEntryTime,
		ModifiedDate:       1<<5 | 1,
		NonUTF8:            f.NonUTF8,
		CRC32:              f.CRC32,
		CompressedSize64:   f.CompressedSize64,
		UncompressedSize64: f.UncompressedSize64,
	})
	if err != nil {
		return fmt.Errorf("failed to create ZIP entry %s: %w", f.Name, err)
	}
	if _, err := io.Copy(dst, raw); err != nil {
		return fmt.Errorf("failed to copy ZIP entry %s: %w", f.Name, err)
	}
	return nil
}

// filterContentTypes removes Override entries referencing metadata from [Content_Types].xml.
func filterContentTypes(data []byte) ([]byte, error) {
	if len(data) > maxXMLEntrySize {
		return nil, fmt.Errorf("[Content_Types].xml too large: %d bytes", len(data))
	}

	var ct contentTypes
	if err := xml.Unmarshal(data, &ct); err != nil {
		return nil, fmt.Errorf("parse [Content_Types].xml: %w", err)
	}

	filtered := make([]contentOverride, 0, len(ct.Overrides))
	for _, o := range ct.Overrides {
		// PartName is like "/docProps/core.xml" — normalize leading slash
		normalized := strings.TrimPrefix(o.PartName, "/")
		if !isMetadataPath(normalized) {
			filtered = append(filtered, o)
		}
	}
	ct.Overrides = filtered

	ct.XMLName = xml.Name{Space: nsContentTypes, Local: "Types"}
	output, err := xml.MarshalIndent(ct, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal [Content_Types].xml: %w", err)
	}

	return append([]byte(officeXMLHeader), output...), nil
}

// filterRelationships removes Relationship entries targeting metadata from _rels/.rels.
func filterRelationships(data []byte) ([]byte, error) {
	if len(data) > maxXMLEntrySize {
		return nil, fmt.Errorf("_rels/.rels too large: %d bytes", len(data))
	}

	var rels relationships
	if err := xml.Unmarshal(data, &rels); err != nil {
		return nil, fmt.Errorf("parse _rels/.rels: %w", err)
	}

	filtered := make([]relationship, 0, len(rels.Rels))
	for _, r := range rels.Rels {
		// Normalize leading slash for absolute pack URIs
		normalizedTarget := strings.TrimPrefix(r.Target, "/")
		if !isMetadataPath(normalizedTarget) {
			filtered = append(filtered, r)
		}
	}
	rels.Rels = filtered

	rels.XMLName = xml.Name{Space: nsRelationships, Local: "Relationships"}
	output, err := xml.MarshalIndent(rels, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal _rels/.rels: %w", err)
	}

	return append([]byte(officeXMLHeader), output...), nil
}
