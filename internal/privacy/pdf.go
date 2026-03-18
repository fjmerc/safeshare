package privacy

import (
	"errors"
	"fmt"
	"os"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// pdfInfoKeys are the Info dictionary entries that identify the author or
// processing history of a PDF document. All are stripped; the PDF spec marks
// them as optional.
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

// stripPDFMetadata removes identifying metadata from a PDF file in-place.
//
// It clears the Info dictionary entries (Author, Creator, Producer,
// CreationDate, ModDate, Subject, Keywords, Title), removes any XMP metadata
// stream attached to the document catalog, and clears the document ID array.
//
// Encrypted or password-protected PDFs are skipped gracefully (nil is
// returned) because modifying their structure without the owner password would
// corrupt the file.
//
// The caller (metadata.go / StripFileMetadata) is responsible for the
// maxStrippableFileSize guard; this function does not duplicate that check.
func stripPDFMetadata(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open PDF file: %w", err)
	}

	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed

	ctx, err := api.ReadValidateAndOptimize(f, conf)
	f.Close()

	if err != nil {
		// pdfcpu returns ErrWrongPassword when the document requires a password
		// for reading (open password) or when it is encrypted but we have no key.
		// In both cases we cannot safely rewrite the file, so skip gracefully.
		if errors.Is(err, pdfcpu.ErrWrongPassword) {
			return nil
		}
		return fmt.Errorf("read PDF: %w", err)
	}

	// A non-nil Encrypt field means the document carries an encryption
	// dictionary. Rewriting encrypted PDFs without the owner password risks
	// corrupting the file, so skip them gracefully.
	if ctx.XRefTable.Encrypt != nil {
		return nil
	}

	// --- Clear Info dictionary entries ---
	if ctx.XRefTable.Info != nil {
		d, err := ctx.XRefTable.DereferenceDict(*ctx.XRefTable.Info)
		if err != nil {
			return fmt.Errorf("dereference Info dict: %w", err)
		}
		if d != nil {
			for _, key := range pdfInfoKeys {
				d.Delete(key)
			}
		}
		// Discard the info dict reference entirely so pdfcpu does not
		// re-inject Producer/CreationDate/ModDate on write.
		ctx.XRefTable.Info = nil
	}

	// --- Remove XMP metadata from the document catalog ---
	catalog, err := ctx.XRefTable.Catalog()
	if err != nil {
		return fmt.Errorf("get PDF catalog: %w", err)
	}
	if _, found := catalog.Find("Metadata"); found {
		catalog.Delete("Metadata")
	}

	// --- Clear the document ID array ---
	// The ID array (two hex strings) links document revisions and can be
	// used to correlate different versions of the same file.
	ctx.XRefTable.ID = nil

	// --- Write back to file atomically ---
	tmpPath := filePath + ".strip-tmp"
	if err := api.WriteContextFile(ctx, tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write stripped PDF: %w", err)
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
