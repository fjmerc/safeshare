package privacy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// pdfInfoKeys are the standard Info dictionary entries that identify the author or
// processing history of a PDF document. The stripper empties the whole
// dictionary; the tests use this list to check that these keys are gone.
var pdfInfoKeys = []string{
	"Author",
	"Creator",
	"Producer",
	"CreationDate",
	"ModDate",
	"Subject",
	"Keywords",
	"Title",
}

// pdfStripTimeout limits how long pdfcpu may spend parsing, optimizing and
// rewriting one PDF, so a crafted file can't keep an upload (and a CPU) busy
// indefinitely. The limit is best-effort: pdfcpu only observes the deadline at
// its checkpoints, so one long uninterrupted step can overrun it (an overrun is
// still rejected). For direct uploads it fits well inside the per-request
// deadline set in handlers/upload.go (at least 120s), so the client gets a
// clean 422 rather than a dropped connection.
//
// A var so tests can shorten it; tests that change it must not use t.Parallel.
var pdfStripTimeout = 60 * time.Second

// StripTimeout is the longest stripping one file may take (the PDF
// stripper's limit; the others don't take long). Callers that wait on
// stripping budget their own deadlines with it.
func StripTimeout() time.Duration { return pdfStripTimeout }

// stripPDFMetadata removes identifying metadata from a PDF file in-place.
//
// It clears the Info dictionary entries (Author, Creator, Producer,
// CreationDate, ModDate, Subject, Keywords, Title), removes any XMP metadata
// stream attached to the document catalog, and clears the document ID array.
//
// Encrypted or password-protected PDFs are left untouched and reported with
// ErrEncryptedDocument, because modifying their structure without the owner
// password would corrupt the file.
//
// The caller (metadata.go / StripFileMetadata) is responsible for the
// maxStrippableFileSize guard; this function does not duplicate that check.
func stripPDFMetadata(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("open PDF file: %w", err)
	}

	// One deadline covers read, validate, optimize and write; pdfcpu checks
	// the context throughout.
	stripCtx, cancel := context.WithTimeout(context.Background(), pdfStripTimeout)
	defer cancel()

	ctx, err := readAndCleanPDF(stripCtx, data)
	if err != nil {
		return err
	}
	return writeStrippedPDF(stripCtx, ctx, filePath)
}

// stripPDFBytes is stripPDFMetadata on an in-memory file: the cleaned PDF
// is written to memory, never to disk. pdfcpu always rewrites the file, so
// it always reports a change.
func stripPDFBytes(data []byte) ([]byte, bool, error) {
	stripCtx, cancel := context.WithTimeout(context.Background(), pdfStripTimeout)
	defer cancel()

	ctx, err := readAndCleanPDF(stripCtx, data)
	if err != nil {
		return nil, false, err
	}
	var out bytes.Buffer
	out.Grow(len(data))
	if err := checkPDFWrite(stripCtx, api.WriteContext(stripCtx, ctx, &out)); err != nil {
		return nil, false, err
	}
	return out.Bytes(), true, nil
}

// checkPDFWrite maps the result of writing a cleaned PDF to the stripper's
// errors. A write that overran its deadline is discarded (fail closed) even
// when it reports success.
func checkPDFWrite(stripCtx context.Context, err error) error {
	if stripCtx.Err() != nil {
		return fmt.Errorf("%w: write PDF", ErrStripTimeout)
	}
	if err != nil {
		return fmt.Errorf("write stripped PDF: %w", err)
	}
	return nil
}

// maxPDFObjects caps the objects in a PDF the stripper parses: pdfcpu holds
// every object in memory (a few KB each), so a crafted file of a million
// tiny objects would take gigabytes. Long real documents have tens of
// thousands.
const maxPDFObjects = 100_000

var (
	// Only object streams have /First, so looking for it as well finds one
	// even without its /Type.
	pdfObjStmMarkers = [][]byte{[]byte("/ObjStm"), []byte("/First")}
	pdfNameEscape    = regexp.MustCompile(`#[0-9A-Fa-f]{2}`)
)

// checkPDFObjectCount estimates the objects in data without parsing it:
// each plain object has an "obj" and usually an "endobj" keyword, and each
// object stream says in its dictionary, as /N, how many it holds. Name
// escapes (/Obj#53tm) are decoded first. An object stream whose dictionary
// can't be read plainly, or whose /N is missing or an indirect reference,
// can't be checked and is refused.
func checkPDFObjectCount(data []byte) error {
	objects := int64(bytes.Count(data, []byte("obj")) / 2)
	if bytes.IndexByte(data, '#') >= 0 {
		data = pdfNameEscape.ReplaceAllFunc(data, func(m []byte) []byte {
			b, _ := strconv.ParseUint(string(m[1:]), 16, 8)
			return []byte{byte(b)}
		})
	}
	seen := map[int]bool{}
	for _, marker := range pdfObjStmMarkers {
		for at := 0; ; {
			i := bytes.Index(data[at:], marker)
			if i < 0 {
				break
			}
			pos := at + i
			at = pos + len(marker)
			if at < len(data) && !isPDFDelimiter(data[at]) {
				continue // a longer name, such as /FirstChar
			}
			start, end, ok := pdfEnclosingDict(data, pos)
			if !ok {
				return fmt.Errorf("PDF object stream dictionary can't be checked")
			}
			if seen[start] {
				continue
			}
			seen[start] = true
			n, ok := pdfDictDirectInt(data[start:end], "/N")
			if !ok {
				return fmt.Errorf("PDF object stream without a readable object count")
			}
			if n > maxPDFObjects {
				return fmt.Errorf("PDF has too many objects")
			}
			objects += n
		}
	}
	if objects > maxPDFObjects {
		return fmt.Errorf("PDF has too many objects (about %d, max %d)", objects, maxPDFObjects)
	}
	return nil
}

func isPDFDelimiter(c byte) bool {
	return strings.IndexByte(" \t\r\n\f\x00/<>[]()%", c) >= 0
}

// pdfEnclosingDict finds the dictionary around pos: the "<<" before it and
// the matching ">>" after it, within 4 KB either way. A string or a comment
// anywhere in it could hide or fake keys and brackets, so that is reported
// as not found.
func pdfEnclosingDict(data []byte, pos int) (start, end int, ok bool) {
	depth := 0
	for i := pos - 1; i > 0 && i >= pos-4096; i-- {
		switch {
		case data[i] == '(' || data[i] == ')' || data[i] == '%':
			return 0, 0, false
		case data[i-1] == '>' && data[i] == '>':
			depth++
			i--
		case data[i-1] == '<' && data[i] == '<':
			if depth == 0 {
				start = i - 1
				goto forward
			}
			depth--
			i--
		}
	}
	return 0, 0, false
forward:
	depth = 0
	for i := pos; i+1 < len(data) && i <= pos+4096; i++ {
		switch {
		case data[i] == '(' || data[i] == ')' || data[i] == '%':
			return 0, 0, false
		case data[i] == '<' && data[i+1] == '<':
			depth++
			i++
		case data[i] == '>' && data[i+1] == '>':
			if depth == 0 {
				return start, i + 2, true
			}
			depth--
			i++
		}
	}
	return 0, 0, false
}

// pdfDictDirectInt returns the value of key in the top level of dict (the
// bytes from "<<" to ">>"), if it is a plain non-negative integer and the
// key appears there exactly once.
func pdfDictDirectInt(dict []byte, key string) (int64, bool) {
	found, value := 0, int64(-1)
	depth := 0
	for i := 2; i < len(dict)-2; i++ {
		switch {
		case dict[i] == '<' && dict[i+1] == '<':
			depth++
			i++
		case dict[i] == '>' && dict[i+1] == '>':
			depth--
			i++
		case dict[i] == '[':
			depth++
		case dict[i] == ']':
			depth--
		case depth == 0 && bytes.HasPrefix(dict[i:], []byte(key)) && i+len(key) < len(dict) && isPDFDelimiter(dict[i+len(key)]):
			found++
			rest := dict[i+len(key):]
			m := pdfDirectInt.FindSubmatch(rest)
			if m == nil {
				return 0, false
			}
			n, err := strconv.ParseInt(string(m[1]), 10, 64)
			if err != nil {
				return 0, false
			}
			value = n
		}
	}
	return value, found == 1 && value >= 0
}

// pdfDirectInt matches an integer that isn't the start of an indirect
// reference ("7 0 R").
var pdfDirectInt = regexp.MustCompile(`^\s*(\d+)(?:\s*/|\s*>>|\s+/|\s*$)`)

// pdfAnnotationIdentityKeys are the entries in an annotation (comment,
// highlight, note) that identify who made it and when.
var pdfAnnotationIdentityKeys = []string{"T", "M", "CreationDate", "NM"}

// cleanPDFObjects removes metadata kept outside the Info dictionary and
// the catalog: XMP and PieceInfo attached to pages, images and other
// objects, and annotation authors and dates.
func cleanPDFObjects(ctx *model.Context) {
	for _, entry := range ctx.XRefTable.Table {
		if entry == nil || entry.Free {
			continue
		}
		var d types.Dict
		switch o := entry.Object.(type) {
		case types.Dict:
			d = o
		case types.StreamDict:
			d = o.Dict
		default:
			continue
		}
		d.Delete("Metadata")
		d.Delete("PieceInfo")
		typ := d.NameEntry("Type")
		_, hasRect := d.Find("Rect")
		_, hasSubtype := d.Find("Subtype")
		if (typ != nil && *typ == "Annot") || (hasRect && hasSubtype && typ == nil) {
			for _, key := range pdfAnnotationIdentityKeys {
				d.Delete(key)
			}
		}
	}
}

// readAndCleanPDF parses the PDF in data and removes its metadata from the
// parsed document (see stripPDFMetadata), ready to be written out.
func readAndCleanPDF(stripCtx context.Context, data []byte) (*model.Context, error) {
	if err := checkPDFObjectCount(data); err != nil {
		return nil, err
	}
	r := bytes.NewReader(data)
	// Stateless configuration: pdfcpu must not read or create config files
	// under $HOME/.config. model.NewDefaultConfiguration() does, and since
	// pdfcpu v0.16 it panics (outside any recover) when it finds a config.yml
	// written by an older version.
	conf := model.NewStatelessConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	// Without this, pdfcpu's writer stamps the Info dictionary with its own
	// Producer and the current time as CreationDate/ModDate, which would
	// record when the file was cleaned. With it, the emptied dictionary
	// below is written as it is.
	conf.PreserveInfoDict = true

	// nil ProgressOptions disables progress reporting.
	ctx, err := api.ReadValidateAndOptimize(stripCtx, r, conf, nil)

	// Check the deadline ourselves rather than relying on how pdfcpu wraps
	// the context error.
	if stripCtx.Err() != nil {
		if err != nil {
			return nil, fmt.Errorf("%w: read PDF: %w", ErrStripTimeout, err)
		}
		return nil, fmt.Errorf("%w: read PDF", ErrStripTimeout)
	}
	if err != nil {
		// pdfcpu returns ErrWrongPassword when the document requires a password
		// for reading (open password) or when it is encrypted but we have no key.
		// In both cases we cannot safely rewrite the file.
		if errors.Is(err, pdfcpu.ErrWrongPassword) {
			return nil, ErrEncryptedDocument
		}
		return nil, fmt.Errorf("read PDF: %w", err)
	}

	// A non-nil Encrypt field means the document carries an encryption
	// dictionary. Rewriting encrypted PDFs without the owner password risks
	// corrupting the file, so leave it untouched.
	if ctx.XRefTable.Encrypt != nil {
		return nil, ErrEncryptedDocument
	}

	// --- Replace the Info dictionary with an empty one ---
	// Every entry goes, not only pdfInfoKeys: custom keys can identify the
	// author too. An empty dictionary rather than none, because pdfcpu
	// writes a fresh, timestamped one when there is none (PDF < 2.0).
	empty, err := ctx.XRefTable.IndRefForNewObject(types.NewDict())
	if err != nil {
		return nil, fmt.Errorf("create empty Info dict: %w", err)
	}
	ctx.XRefTable.Info = empty

	// --- Remove XMP metadata from the document catalog ---
	catalog, err := ctx.XRefTable.Catalog()
	if err != nil {
		return nil, fmt.Errorf("get PDF catalog: %w", err)
	}
	if _, found := catalog.Find("Metadata"); found {
		catalog.Delete("Metadata")
	}

	// --- Metadata elsewhere: pages, images, annotations ---
	cleanPDFObjects(ctx)

	// --- Clear the document ID array ---
	// The ID array (two hex strings) links document revisions and can be
	// used to correlate different versions of the same file.
	ctx.XRefTable.ID = nil

	return ctx, nil
}

// writeStrippedPDF writes ctx to a temp file next to filePath and atomically
// replaces filePath with it. The original is left untouched on any failure,
// including the deadline expiring.
func writeStrippedPDF(stripCtx context.Context, ctx *model.Context, filePath string) error {
	tmpPath := filePath + ".strip-tmp"
	// Also covers a panic inside pdfcpu's writer (recovered by the callers);
	// a no-op once the rename below has succeeded.
	defer os.Remove(tmpPath)
	// Check the deadline even when the write reports success: a write that
	// overran its deadline is discarded (fail closed) rather than trusted.
	if err := checkPDFWrite(stripCtx, api.WriteContextFile(stripCtx, ctx, tmpPath)); err != nil {
		os.Remove(tmpPath)
		return err
	}

	info, err := os.Stat(filePath)
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("stat original PDF: %w", err)
	}

	if err := os.Chmod(tmpPath, info.Mode().Perm()); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod stripped PDF: %w", err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replace PDF with stripped version: %w", err)
	}

	return nil
}
