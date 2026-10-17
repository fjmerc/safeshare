package privacy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

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
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open PDF file: %w", err)
	}

	// Stateless configuration: pdfcpu must not read or create config files
	// under $HOME/.config. model.NewDefaultConfiguration() does, and since
	// pdfcpu v0.16 it panics (outside any recover) when it finds a config.yml
	// written by an older version.
	conf := model.NewStatelessConfiguration()
	conf.ValidationMode = model.ValidationRelaxed

	// One deadline covers read, validate, optimize and write; pdfcpu checks
	// the context throughout. nil ProgressOptions disables progress reporting.
	stripCtx, cancel := context.WithTimeout(context.Background(), pdfStripTimeout)
	defer cancel()

	ctx, err := api.ReadValidateAndOptimize(stripCtx, f, conf, nil)
	f.Close()

	// Check the deadline ourselves rather than relying on how pdfcpu wraps
	// the context error.
	if stripCtx.Err() != nil {
		if err != nil {
			return fmt.Errorf("%w: read PDF: %w", ErrStripTimeout, err)
		}
		return fmt.Errorf("%w: read PDF", ErrStripTimeout)
	}
	if err != nil {
		// pdfcpu returns ErrWrongPassword when the document requires a password
		// for reading (open password) or when it is encrypted but we have no key.
		// In both cases we cannot safely rewrite the file.
		if errors.Is(err, pdfcpu.ErrWrongPassword) {
			return ErrEncryptedDocument
		}
		return fmt.Errorf("read PDF: %w", err)
	}

	// A non-nil Encrypt field means the document carries an encryption
	// dictionary. Rewriting encrypted PDFs without the owner password risks
	// corrupting the file, so leave it untouched.
	if ctx.XRefTable.Encrypt != nil {
		return ErrEncryptedDocument
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

	return writeStrippedPDF(stripCtx, ctx, filePath)
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
	if err := api.WriteContextFile(stripCtx, ctx, tmpPath); err != nil || stripCtx.Err() != nil {
		os.Remove(tmpPath)
		if stripCtx.Err() != nil {
			return fmt.Errorf("%w: write PDF", ErrStripTimeout)
		}
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
