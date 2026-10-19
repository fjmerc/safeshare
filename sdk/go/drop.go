package safeshare

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"

	"filippo.io/age"
)

// DropFilename is the name the server stores drop-page submissions under:
// a tar archive, padded with zero bytes, encrypted with age to the server's
// DROP_RECIPIENT key.
const DropFilename = "safeshare-drop.tar.age"

// ageHeader starts every binary (not armored) age file.
const ageHeader = "age-encryption.org/v1\n"

// maxDropEntries is far more than the server writes (the file and
// message.txt), so a forged archive cannot create files without limit.
const maxDropEntries = 16

var (
	// ErrNotDrop indicates the downloaded file is not an age-encrypted drop.
	ErrNotDrop = errors.New("not an age-encrypted drop")
	// ErrDirectoryExists indicates a drop's destination directory already
	// exists; drops are only extracted into a new one.
	ErrDirectoryExists = errors.New("destination directory already exists")
)

// DropFile is one file extracted from a drop.
type DropFile struct {
	// Name is the file's name inside the destination directory. It comes
	// from the sender, made safe with SafeFilename.
	Name string
	// Size is the file's size in bytes.
	Size int64
}

// CheckDropDestination returns ErrDirectoryExists if dir exists; ExtractDrop
// creates it, in a parent directory that must exist. Call it before
// downloading, since a download may count against the file's limit.
func CheckDropDestination(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("%w: %s", ErrDirectoryExists, dir)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking destination: %w", err)
	}
	return nil
}

// DownloadDrop downloads a drop-page submission, decrypts it with one of
// identities (the recipient's age private key; see age.ParseIdentities) and
// extracts it into dir, which must not exist yet. The download streams; it
// is not held in memory. opts.Password and opts.OnProgress are used;
// Overwrite and DecryptionKey are not. See ExtractDrop for what is written.
func (c *Client) DownloadDrop(ctx context.Context, claimCode, dir string, identities []age.Identity, opts *DownloadOptions) ([]DropFile, error) {
	if err := validateClaimCode(claimCode); err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("%w: no age identity given", ErrValidation)
	}
	if err := CheckDropDestination(dir); err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &DownloadOptions{}
	}

	resp, err := c.requestWithPassword(ctx, http.MethodGet, "/api/claim/"+claimCode, nil, "", opts.Password)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, handleResponse(resp, nil)
	}

	var body io.Reader = resp.Body
	if opts.OnProgress != nil {
		total, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
		body = &progressDownloadReader{reader: resp.Body, totalBytes: total, onProgress: opts.OnProgress}
	}
	return ExtractDrop(body, identities, dir)
}

// ExtractDrop decrypts a drop (as downloaded, "safeshare-drop.tar.age") with
// one of identities and extracts it into dir, which must not exist yet and
// is created with mode 0700 (its parent must exist). Each file is written with mode 0600 under its
// name made safe with SafeFilename; nothing is written outside dir.
//
// The server only writes regular files, so an archive containing anything
// else (a directory, a link, a device, a sparse file), more than a few
// entries, two files
// whose names clash, or data after its end other than the zero padding is
// refused. Decryption is checked to the last byte: if anything fails,
// including a truncated or modified download, dir and everything in it are
// removed and an error is returned.
func ExtractDrop(r io.Reader, identities []age.Identity, dir string) (files []DropFile, err error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("%w: no age identity given", ErrValidation)
	}
	if err := CheckDropDestination(dir); err != nil {
		return nil, err
	}

	br := bufio.NewReader(r)
	head, err := br.Peek(len(ageHeader))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("downloading drop: %w", err)
	}
	if string(head) != ageHeader {
		return nil, fmt.Errorf("%w: the file does not start with an age header", ErrNotDrop)
	}
	plain, err := age.Decrypt(br, identities...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, errors.New("decrypting drop: it was not encrypted to this key")
		}
		return nil, fmt.Errorf("decrypting drop: %w", err)
	}

	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrDirectoryExists, dir)
		}
		return nil, fmt.Errorf("creating destination directory: %w", err)
	}
	// Files are created through root, so they land in this directory even
	// if its path is swapped for a link while extracting.
	root, err := os.OpenRoot(dir)
	if err != nil {
		os.Remove(dir)
		return nil, fmt.Errorf("opening destination directory: %w", err)
	}
	defer func() {
		root.Close()
		if err != nil {
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				err = fmt.Errorf("%w (and removing %s failed: %v)", err, dir, rmErr)
			}
			files = nil
		}
	}()

	tr := tar.NewReader(plain)
	seen := make(map[string]bool)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading drop archive: %w", err)
		}
		if len(files) == maxDropEntries {
			return nil, fmt.Errorf("reading drop archive: more than %d entries", maxDropEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("reading drop archive: entry %d is not a regular file", len(files)+1)
		}
		// A sparse file's holes would be written out as zeros: a tiny
		// archive could fill the disk.
		for k := range hdr.PAXRecords {
			if strings.HasPrefix(k, "GNU.sparse.") {
				return nil, fmt.Errorf("reading drop archive: entry %d is a sparse file", len(files)+1)
			}
		}
		if hdr.Size < 0 {
			return nil, fmt.Errorf("reading drop archive: entry %d has an invalid size", len(files)+1)
		}
		name := SafeFilename(hdr.Name, "file-"+strconv.Itoa(len(files)+1))
		// Refuse names that would clash on a case-insensitive file system.
		key := strings.ToLower(name)
		if seen[key] {
			return nil, fmt.Errorf("reading drop archive: two entries are named %q", name)
		}
		seen[key] = true
		if err := writeDropEntry(root, name, tr, hdr.Size); err != nil {
			return nil, err
		}
		files = append(files, DropFile{Name: name, Size: hdr.Size})
	}

	// Read the rest, which also checks the end of the age stream: only the
	// zero padding may follow the archive.
	if err := checkZeroPadding(plain); err != nil {
		return nil, err
	}
	return files, nil
}

// writeDropEntry creates name in root (it must not exist) with mode 0600
// and copies exactly size bytes from r into it.
func writeDropEntry(root *os.Root, name string, r io.Reader, size int64) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating %q: %w", name, err)
	}
	if _, err := io.CopyN(f, r, size); err != nil {
		f.Close()
		return fmt.Errorf("reading drop archive: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("writing %q: %w", name, err)
	}
	return nil
}

// checkZeroPadding reads r to its end and fails if any byte is not zero.
func checkZeroPadding(r io.Reader) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		for _, c := range buf[:n] {
			if c != 0 {
				return fmt.Errorf("reading drop archive: unexpected data after the archive")
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("decrypting drop: %w", err)
		}
	}
}
