package safeshare

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"filippo.io/age"
)

type dropEntry struct {
	name     string
	body     string
	typeflag byte
	linkname string
}

// buildDrop makes a drop the way the server does: a tar archive (mtime 0,
// mode 0644), followed by pad zero bytes, encrypted to recipient.
func buildDrop(t *testing.T, recipient age.Recipient, entries []dropEntry, pad []byte) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: typeflag, Linkname: e.linkname}
		if typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tarBuf.Write(pad)

	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func newX25519(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s exists after a failed extraction (err %v)", path, err)
	}
}

func TestExtractDrop(t *testing.T) {
	id := newX25519(t)
	longName := strings.Repeat("n", 196) + ".pdf" // no slash: needs a PAX header
	blob := buildDrop(t, id.Recipient(), []dropEntry{
		{name: longName, body: "%PDF-1.7 report"},
		{name: "message.txt", body: "hello from the source"},
	}, make([]byte, 5000))

	dir := filepath.Join(t.TempDir(), "out")
	files, err := ExtractDrop(bytes.NewReader(blob), []age.Identity{id}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Name != longName || files[0].Size != 15 || files[1].Name != "message.txt" {
		t.Fatalf("files = %+v", files)
	}
	for name, want := range map[string]string{longName: "%PDF-1.7 report", "message.txt": "hello from the source"} {
		path := filepath.Join(dir, name)
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v", name, got, err)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", name, info.Mode().Perm())
		}
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v, want 0700", info.Mode().Perm())
	}
}

func TestExtractDropPostQuantum(t *testing.T) {
	id, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	blob := buildDrop(t, id.Recipient(), []dropEntry{{name: "a.txt", body: "pq"}}, nil)
	dir := filepath.Join(t.TempDir(), "out")
	if _, err := ExtractDrop(bytes.NewReader(blob), []age.Identity{id}, dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "a.txt")); string(got) != "pq" {
		t.Fatalf("a.txt = %q", got)
	}
}

func TestExtractDropKeyFileFromAgeKeygen(t *testing.T) {
	id := newX25519(t)
	keyFile := "# created: 2026-10-19T00:00:00Z\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	ids, err := age.ParseIdentities(strings.NewReader(keyFile))
	if err != nil {
		t.Fatal(err)
	}
	blob := buildDrop(t, id.Recipient(), []dropEntry{{name: "a.txt", body: "x"}}, nil)
	if _, err := ExtractDrop(bytes.NewReader(blob), ids, filepath.Join(t.TempDir(), "out")); err != nil {
		t.Fatal(err)
	}
}

// Names are reduced to plain base names inside the destination.
func TestExtractDropSanitisesNames(t *testing.T) {
	id := newX25519(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "out")
	blob := buildDrop(t, id.Recipient(), []dropEntry{
		{name: "../escape.txt", body: "1"},
		{name: "/etc/abs.txt", body: "2"},
		{name: "sub/dir/nested.txt", body: "3"},
		{name: ".bashrc", body: "4"},
		{name: "..", body: "5"},
	}, nil)
	files, err := ExtractDrop(bytes.NewReader(blob), []age.Identity{id}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	if got := strings.Join(names, ","); got != "escape.txt,abs.txt,nested.txt,bashrc,file-5" {
		t.Fatalf("names = %s", got)
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 || entries[0].Name() != "out" {
		t.Fatalf("parent holds %v, want only out", entries)
	}
}

func TestExtractDropRefusals(t *testing.T) {
	id := newX25519(t)
	var many []dropEntry
	for i := 0; i <= maxDropEntries; i++ {
		many = append(many, dropEntry{name: "f" + strings.Repeat("x", i), body: "x"})
	}
	cases := map[string][]byte{
		"symlink":        buildDrop(t, id.Recipient(), []dropEntry{{name: "a.txt", body: "ok"}, {name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}}, nil),
		"hardlink":       buildDrop(t, id.Recipient(), []dropEntry{{name: "link", typeflag: tar.TypeLink, linkname: "a.txt"}}, nil),
		"directory":      buildDrop(t, id.Recipient(), []dropEntry{{name: "d/", typeflag: tar.TypeDir}}, nil),
		"case clash":     buildDrop(t, id.Recipient(), []dropEntry{{name: "Report.pdf", body: "1"}, {name: "report.PDF", body: "2"}}, nil),
		"sanitise clash": buildDrop(t, id.Recipient(), []dropEntry{{name: "a/x.txt", body: "1"}, {name: "b/x.txt", body: "2"}}, nil),
		"too many":       buildDrop(t, id.Recipient(), many, nil),
		"trailing data":  buildDrop(t, id.Recipient(), []dropEntry{{name: "a.txt", body: "ok"}}, append(make([]byte, 600), 'X')),
		"not age":        []byte("PK\x03\x04 a zip file, not a drop"),
		"empty":          nil,
		"not a tar":      buildDropRaw(t, id.Recipient(), []byte("plain text, not an archive at all")),
		"wrong key":      buildDrop(t, newX25519(t).Recipient(), []dropEntry{{name: "a.txt", body: "ok"}}, nil),
	}
	good := buildDrop(t, id.Recipient(), []dropEntry{{name: "a.txt", body: strings.Repeat("ok", 50000)}}, make([]byte, 4096))
	cases["truncated"] = good[:len(good)-100]
	cases["sparse"] = buildDropRaw(t, id.Recipient(), sparseTar(1<<20))
	tampered := bytes.Clone(good)
	tampered[len(tampered)-1] ^= 1
	cases["tampered"] = tampered

	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "out")
			files, err := ExtractDrop(bytes.NewReader(blob), []age.Identity{id}, dir)
			if err == nil {
				t.Fatalf("extracted %+v, want an error", files)
			}
			if files != nil {
				t.Errorf("files = %+v on error", files)
			}
			t.Logf("%s: %v", name, err)
			assertNotExist(t, dir)
		})
	}
	if _, err := ExtractDrop(bytes.NewReader(cases["not age"]), []age.Identity{id}, filepath.Join(t.TempDir(), "out")); !errors.Is(err, ErrNotDrop) {
		t.Errorf("not age: err = %v, want ErrNotDrop", err)
	}
	if _, err := ExtractDrop(bytes.NewReader(cases["wrong key"]), []age.Identity{id}, filepath.Join(t.TempDir(), "out")); err == nil || !strings.Contains(err.Error(), "not encrypted to this key") {
		t.Errorf("wrong key: err = %v", err)
	}
}

func buildDropRaw(t *testing.T, recipient age.Recipient, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := age.Encrypt(&out, recipient)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(plain)
	w.Close()
	return out.Bytes()
}

func TestExtractDropDestinationExists(t *testing.T) {
	id := newX25519(t)
	blob := buildDrop(t, id.Recipient(), []dropEntry{{name: "a.txt", body: "ok"}}, nil)
	dir := t.TempDir() // exists, empty
	if _, err := ExtractDrop(bytes.NewReader(blob), []age.Identity{id}, dir); !errors.Is(err, ErrDirectoryExists) {
		t.Fatalf("err = %v, want ErrDirectoryExists", err)
	}
	// The parent is not created.
	if _, err := ExtractDrop(bytes.NewReader(blob), []age.Identity{id}, filepath.Join(dir, "a", "b")); err == nil {
		t.Fatal("extracted into a missing parent")
	}
	assertNotExist(t, filepath.Join(dir, "a"))
	if _, err := ExtractDrop(bytes.NewReader(blob), nil, filepath.Join(dir, "out")); !errors.Is(err, ErrValidation) {
		t.Fatalf("no identities: err = %v", err)
	}
}

func TestDownloadDrop(t *testing.T) {
	id := newX25519(t)
	blob := buildDrop(t, id.Recipient(), []dropEntry{{name: "photo.jpg", body: "jpeg"}, {name: "message.txt", body: "hi"}}, make([]byte, 4096))
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/api/claim/drop1234":
			if r.Header.Get("X-File-Password") != "pw" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"password required","code":"PASSWORD_REQUIRED"}`))
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(blob)
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found","code":"NOT_FOUND"}`))
		}
	}))
	defer srv.Close()
	c, err := NewClient(ClientConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ids := []age.Identity{id}

	var progressed bool
	dir := filepath.Join(t.TempDir(), "drop")
	files, err := c.DownloadDrop(ctx, "drop1234", dir, ids, &DownloadOptions{Password: "pw", OnProgress: func(DownloadProgress) { progressed = true }})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || !progressed {
		t.Fatalf("files = %+v, progress %v", files, progressed)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "message.txt")); string(got) != "hi" {
		t.Fatalf("message.txt = %q", got)
	}

	// The destination is checked before anything is downloaded.
	before := requests.Load()
	if _, err := c.DownloadDrop(ctx, "drop1234", dir, ids, &DownloadOptions{Password: "pw"}); !errors.Is(err, ErrDirectoryExists) {
		t.Fatalf("err = %v, want ErrDirectoryExists", err)
	}
	if requests.Load() != before {
		t.Fatal("downloaded although the destination exists")
	}

	// Server errors leave nothing behind.
	for code, want := range map[string]error{"missing99": ErrNotFound, "drop1234": ErrPasswordRequired} {
		dir := filepath.Join(t.TempDir(), "drop")
		if _, err := c.DownloadDrop(ctx, code, dir, ids, nil); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", code, err, want)
		}
		assertNotExist(t, dir)
	}
}

// rawTarHeader builds a USTAR header block by hand, for entries tar.Writer
// refuses to write.
func rawTarHeader(name string, typeflag byte, size int) []byte {
	h := make([]byte, 512)
	copy(h, name)
	copy(h[100:], "0000644\x00")
	copy(h[108:], "0000000\x00")
	copy(h[116:], "0000000\x00")
	copy(h[124:], fmt.Sprintf("%011o\x00", size))
	copy(h[136:], "00000000000\x00")
	h[156] = typeflag
	copy(h[257:], "ustar\x0000")
	copy(h[148:], "        ")
	sum := 0
	for _, c := range h {
		sum += int(c)
	}
	copy(h[148:], fmt.Sprintf("%06o\x00 ", sum))
	return h
}

func paxRecord(k, v string) string {
	rec := " " + k + "=" + v + "\n"
	n := len(rec) + 1
	for len(fmt.Sprint(n))+len(rec) != n {
		n = len(fmt.Sprint(n)) + len(rec)
	}
	return fmt.Sprint(n) + rec
}

// sparseTar is a tar whose one entry, a GNU PAX 0.1 sparse file with no
// data, reads back as realSize zero bytes.
func sparseTar(realSize int) []byte {
	pax := paxRecord("GNU.sparse.major", "0") + paxRecord("GNU.sparse.minor", "1") +
		paxRecord("GNU.sparse.size", fmt.Sprint(realSize)) + paxRecord("GNU.sparse.numblocks", "1") +
		paxRecord("GNU.sparse.map", fmt.Sprintf("%d,0", realSize-1))
	var b bytes.Buffer
	b.Write(rawTarHeader("PaxHeaders/big", 'x', len(pax)))
	b.WriteString(pax)
	b.Write(make([]byte, (512-len(pax)%512)%512))
	b.Write(rawTarHeader("big", '0', 0))
	b.Write(make([]byte, 1024))
	return b.Bytes()
}

// The sparse helper really does expand when read without the check.
func TestSparseTarExpands(t *testing.T) {
	hdr, err := tar.NewReader(bytes.NewReader(sparseTar(1 << 20))).Next()
	if err != nil || hdr.Typeflag != tar.TypeReg || hdr.Size != 1<<20 {
		t.Fatalf("hdr %+v, err %v", hdr, err)
	}
}

func TestExtractDropEdgeEntries(t *testing.T) {
	id := newX25519(t)
	other := newX25519(t)
	blob := buildDrop(t, id.Recipient(), []dropEntry{
		{name: "empty.txt", body: ""},
		{name: "CON.txt", body: "device name"},
	}, nil)
	dir := filepath.Join(t.TempDir(), "out")
	// Any of several identities may match.
	files, err := ExtractDrop(bytes.NewReader(blob), []age.Identity{other, id}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].Size != 0 || files[1].Name != "_CON.txt" {
		t.Fatalf("files = %+v", files)
	}
	if info, err := os.Stat(filepath.Join(dir, "empty.txt")); err != nil || info.Size() != 0 {
		t.Fatalf("empty.txt: %v %v", info, err)
	}
}
