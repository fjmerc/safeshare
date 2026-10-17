package privacy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// pdfFixtureInfo holds the identifying Info dictionary values written into the
// test PDF. Each value is unique so it can be searched for after stripping.
var pdfFixtureInfo = map[string]string{
	"Author":       "FixtureAuthorJaneDoe",
	"Creator":      "FixtureCreatorApp",
	"Producer":     "FixtureProducerLib",
	"CreationDate": "D:20200101120000Z",
	"ModDate":      "D:20210202130000Z",
	"Subject":      "FixtureSubjectSecret",
	"Keywords":     "FixtureKeywordsSecret",
	"Title":        "FixtureTitleSecret",
}

const (
	pdfFixtureXMPMarker = "FixtureXMPCreatorTool"
	pdfFixtureID        = "0123456789ABCDEF0123456789ABCDEF"
)

// buildPDFWithMetadata constructs a minimal, valid single-page PDF carrying
// an Info dictionary with every key in pdfInfoKeys, an XMP metadata stream on
// the catalog, and a trailer /ID array. Cross-reference offsets are computed
// from the buffer so the file parses without repair.
func buildPDFWithMetadata(t *testing.T) []byte {
	t.Helper()

	xmp := `<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>` +
		`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">` +
		`<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/">` +
		`<xmp:CreatorTool>` + pdfFixtureXMPMarker + `</xmp:CreatorTool>` +
		`</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`

	var info strings.Builder
	info.WriteString("<<")
	for _, key := range pdfInfoKeys {
		fmt.Fprintf(&info, " /%s (%s)", key, pdfFixtureInfo[key])
	}
	info.WriteString(" >>")

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
		fmt.Sprintf("<< /Type /Metadata /Subtype /XML /Length %d >>\nstream\n%s\nendstream", len(xmp), xmp),
		info.String(),
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}

	xrefOffset := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Info 5 0 R /ID [<%s> <%s>] >>\n",
		len(objects)+1, pdfFixtureID, pdfFixtureID)
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefOffset)
	return buf.Bytes()
}

// readPDFContext parses and validates a PDF with pdfcpu for structural
// assertions. Validation also proves the stripped output is still a
// well-formed document.
func readPDFContext(t *testing.T, path string) *model.Context {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	conf := model.NewStatelessConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	ctx, err := api.ReadAndValidate(context.Background(), f, conf)
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}
	return ctx
}

// pdfInfoValues returns the Info dictionary entries as strings, or nil when
// the document has no Info dictionary.
func pdfInfoValues(t *testing.T, ctx *model.Context) map[string]string {
	t.Helper()
	if ctx.XRefTable.Info == nil {
		return nil
	}
	d, err := ctx.XRefTable.DereferenceDict(*ctx.XRefTable.Info)
	if err != nil {
		t.Fatalf("dereference Info dict: %v", err)
	}
	values := make(map[string]string, len(d))
	for key, obj := range d {
		o, err := ctx.XRefTable.Dereference(obj)
		if err != nil {
			t.Fatalf("dereference Info entry %s: %v", key, err)
		}
		switch v := o.(type) {
		case types.StringLiteral:
			s, err := types.StringLiteralToString(v)
			if err != nil {
				t.Fatalf("decode Info entry %s: %v", key, err)
			}
			values[key] = s
		case types.HexLiteral:
			s, err := types.HexLiteralToString(v)
			if err != nil {
				t.Fatalf("decode Info entry %s: %v", key, err)
			}
			values[key] = s
		default:
			values[key] = fmt.Sprint(o)
		}
	}
	return values
}

func pdfHasCatalogMetadata(t *testing.T, ctx *model.Context) bool {
	t.Helper()
	catalog, err := ctx.XRefTable.Catalog()
	if err != nil {
		t.Fatalf("get catalog: %v", err)
	}
	_, found := catalog.Find("Metadata")
	return found
}

func pdfIDContainsFixture(ctx *model.Context) bool {
	for _, obj := range ctx.XRefTable.ID {
		if strings.Contains(strings.ToUpper(fmt.Sprint(obj)), pdfFixtureID) {
			return true
		}
	}
	return false
}

func TestStripPDFMetadata_RemovesInfoXMPAndID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.pdf")
	if err := os.WriteFile(path, buildPDFWithMetadata(t), 0o640); err != nil {
		t.Fatal(err)
	}

	// Guard against a vacuous pass: the fixture must carry every piece of
	// metadata the stripper is supposed to remove.
	before := readPDFContext(t, path)
	beforeInfo := pdfInfoValues(t, before)
	for _, key := range pdfInfoKeys {
		if beforeInfo[key] != pdfFixtureInfo[key] {
			t.Fatalf("fixture Info[%s] = %q, want %q", key, beforeInfo[key], pdfFixtureInfo[key])
		}
	}
	if !pdfHasCatalogMetadata(t, before) {
		t.Fatal("fixture catalog has no /Metadata stream")
	}
	if !pdfIDContainsFixture(before) {
		t.Fatalf("fixture trailer /ID = %v, want it to contain %s", before.XRefTable.ID, pdfFixtureID)
	}
	if before.PageCount != 1 {
		t.Fatalf("fixture PageCount = %d, want 1", before.PageCount)
	}

	if err := StripFileMetadata(path, "application/pdf"); err != nil {
		t.Fatalf("StripFileMetadata: %v", err)
	}

	after := readPDFContext(t, path)

	// pdfcpu's writer may synthesise a fresh Info dict (its own Producer and
	// current dates); what matters is that none of the original values survive.
	afterInfo := pdfInfoValues(t, after)
	for _, key := range pdfInfoKeys {
		if got, ok := afterInfo[key]; ok && got == pdfFixtureInfo[key] {
			t.Errorf("Info[%s] still holds original value %q", key, got)
		}
	}
	for _, key := range []string{"Author", "Creator", "Subject", "Keywords", "Title"} {
		if got, ok := afterInfo[key]; ok {
			t.Errorf("Info[%s] present after stripping: %q", key, got)
		}
	}

	if pdfHasCatalogMetadata(t, after) {
		t.Error("catalog /Metadata (XMP) present after stripping")
	}
	if pdfIDContainsFixture(after) {
		t.Errorf("trailer /ID still holds original value: %v", after.XRefTable.ID)
	}

	// Belt and braces: none of the unique fixture strings may appear anywhere
	// in the rewritten bytes.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	needles := []string{pdfFixtureXMPMarker, pdfFixtureID}
	for _, key := range []string{"Author", "Creator", "Producer", "Subject", "Keywords", "Title"} {
		needles = append(needles, pdfFixtureInfo[key])
	}
	for _, needle := range needles {
		if bytes.Contains(bytes.ToUpper(raw), bytes.ToUpper([]byte(needle))) {
			t.Errorf("stripped PDF still contains %q", needle)
		}
	}

	// The page tree must survive: the output is still a one-page document.
	if after.PageCount != 1 {
		t.Errorf("PageCount = %d after stripping, want 1", after.PageCount)
	}

	// The in-place rewrite preserves the original file mode.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("file mode = %v after stripping, want 0640", st.Mode().Perm())
	}
	if _, err := os.Stat(path + ".strip-tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file left behind: %v", err)
	}
}

func TestStripPDFMetadata_EncryptedLeftUntouched(t *testing.T) {
	cases := []struct {
		name   string
		userPW string
	}{
		{"open password", "user-secret"},
		{"owner password only", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf := model.NewStatelessConfiguration()
			conf.UserPW = tc.userPW
			conf.OwnerPW = "owner-secret"
			conf.EncryptUsingAES = true
			conf.EncryptKeyLength = 256

			var enc bytes.Buffer
			if err := api.Encrypt(context.Background(), bytes.NewReader(buildPDFWithMetadata(t)), &enc, conf); err != nil {
				t.Fatalf("encrypt fixture: %v", err)
			}

			path := filepath.Join(t.TempDir(), "enc.pdf")
			if err := os.WriteFile(path, enc.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}

			err := StripFileMetadata(path, "application/pdf")
			if !errors.Is(err, ErrEncryptedDocument) {
				t.Fatalf("expected ErrEncryptedDocument, got %v", err)
			}

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, enc.Bytes()) {
				t.Error("encrypted PDF was modified")
			}
		})
	}
}

func TestStripPDFMetadata_TimeoutLeavesFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.pdf")
	original := buildPDFWithMetadata(t)
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}

	saved := pdfStripTimeout
	pdfStripTimeout = time.Nanosecond
	t.Cleanup(func() { pdfStripTimeout = saved })

	err := StripFileMetadata(path, "application/pdf")
	if !errors.Is(err, ErrStripTimeout) {
		t.Fatalf("expected ErrStripTimeout, got %v", err)
	}
	// Proves the deadline reached pdfcpu itself, not just our own check.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected pdfcpu to report context.DeadlineExceeded, got %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("PDF was modified despite the timeout")
	}
	if _, err := os.Stat(path + ".strip-tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
}

// The test above trips the read-phase deadline. This one covers the write
// phase: a context that expires after a successful read must not replace the
// original or leave a temp file behind.
func TestWriteStrippedPDF_ExpiredContextLeavesFileUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.pdf")
	original := buildPDFWithMetadata(t)
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}
	pdfCtx := readPDFContext(t, path)

	expired, cancel := context.WithCancel(context.Background())
	cancel()

	err := writeStrippedPDF(expired, pdfCtx, path)
	if !errors.Is(err, ErrStripTimeout) {
		t.Fatalf("expected ErrStripTimeout, got %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("PDF was replaced despite the expired context")
	}
	if _, err := os.Stat(path + ".strip-tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: %v", err)
	}
}
