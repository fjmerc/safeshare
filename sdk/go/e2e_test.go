package safeshare

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// e2eVectors mirrors sdk/testdata/e2e-vectors.json, generated from the web
// app's crypto.js by tests/js/e2e-vectors.test.js.
type e2eVectors struct {
	Key       string `json:"key"`
	IV        string `json:"iv"`
	Constants struct {
		PadMinBytes        int64 `json:"pad_min_bytes"`
		CiphertextOverhead int64 `json:"ciphertext_overhead"`
	} `json:"constants"`
	Padme []struct {
		N      int64 `json:"n"`
		Padded int64 `json:"padded"`
	} `json:"padme"`
	PaddedLength []struct {
		N         int64  `json:"n"`
		MaxStored int64  `json:"max_stored"`
		Padded    int64  `json:"padded"`
		Error     string `json:"error"`
	} `json:"padded_length"`
	Wrap []struct {
		ID        string `json:"id"`
		Format    string `json:"format"`
		Name      string `json:"name"`
		Data      string `json:"data"`
		MaxStored int64  `json:"max_stored"`
		Payload   string `json:"payload"`
		Error     string `json:"error"`
	} `json:"wrap"`
	Unwrap []struct {
		ID       string  `json:"id"`
		Payload  string  `json:"payload"`
		Filename *string `json:"filename"`
		Data     string  `json:"data"`
		Version  int     `json:"version"`
		Error    bool    `json:"error"`
	} `json:"unwrap"`
	Encrypt []struct {
		ID      string `json:"id"`
		Payload string `json:"payload"`
		Blob    string `json:"blob"`
	} `json:"encrypt"`
	DecryptFails []struct {
		ID   string `json:"id"`
		Blob string `json:"blob"`
	} `json:"decrypt_fails"`
	ShareURL []struct {
		Base      string `json:"base"`
		ClaimCode string `json:"claim_code"`
		Key       string `json:"key"`
		URL       string `json:"url"`
	} `json:"share_url"`
}

func loadVectors(t *testing.T) *e2eVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "e2e-vectors.json"))
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var v e2eVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestE2EVectorsFromWebApp(t *testing.T) {
	v := loadVectors(t)
	if v.Constants.PadMinBytes != padMinBytes || v.Constants.CiphertextOverhead != CiphertextOverhead {
		t.Fatalf("constants differ from crypto.js: %+v", v.Constants)
	}
	key, err := decodeKey(v.Key)
	if err != nil {
		t.Fatal(err)
	}
	iv := unhex(t, v.IV)

	t.Run("padme", func(t *testing.T) {
		for _, c := range v.Padme {
			if got := padmeLength(c.N); got != c.Padded {
				t.Errorf("padmeLength(%d) = %d, crypto.js %d", c.N, got, c.Padded)
			}
		}
	})

	t.Run("padded length", func(t *testing.T) {
		for _, c := range v.PaddedLength {
			got, err := paddedPayloadLength(c.N, c.MaxStored)
			if c.Error != "" {
				if !errors.Is(err, ErrPayloadTooLarge) {
					t.Errorf("paddedPayloadLength(%d, %d): want ErrPayloadTooLarge, got %d, %v", c.N, c.MaxStored, got, err)
				}
				continue
			}
			if err != nil || got != c.Padded {
				t.Errorf("paddedPayloadLength(%d, %d) = %d, %v; crypto.js %d", c.N, c.MaxStored, got, err, c.Padded)
			}
		}
	})

	t.Run("wrap", func(t *testing.T) {
		for _, c := range v.Wrap {
			data := unhex(t, c.Data)
			got, err := wrapPayload(c.Name, data, c.Format == "SF02", c.MaxStored)
			if c.Error != "" {
				if !errors.Is(err, ErrPayloadTooLarge) {
					t.Errorf("%s: want ErrPayloadTooLarge, got %v", c.ID, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s: %v", c.ID, err)
				continue
			}
			if want := unhex(t, c.Payload); !bytes.Equal(got, want) {
				t.Errorf("%s: payload differs from crypto.js (len %d vs %d)", c.ID, len(got), len(want))
			}
			// The streaming layout used for file uploads must agree too.
			l, err := framePayload(c.Name, int64(len(data)), c.Format == "SF02", c.MaxStored)
			if err != nil || l.total != int64(len(got)) || !bytes.HasPrefix(got, l.header) {
				t.Errorf("%s: framePayload disagrees with wrapPayload: %+v %v", c.ID, l, err)
			}
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		for _, c := range v.Unwrap {
			got, err := unwrapPayload(unhex(t, c.Payload))
			if c.Error {
				if !errors.Is(err, ErrInvalidPayload) {
					t.Errorf("%s: want ErrInvalidPayload, got %+v, %v", c.ID, got, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s: %v", c.ID, err)
				continue
			}
			wantName := ""
			if c.Filename != nil {
				wantName = *c.Filename
			}
			if got.filename != wantName || got.version != c.Version || !bytes.Equal(got.data, unhex(t, c.Data)) {
				t.Errorf("%s: got name %q v%d len %d; crypto.js name %q v%d", c.ID, got.filename, got.version, len(got.data), wantName, c.Version)
			}
		}
	})

	t.Run("encrypt and decrypt", func(t *testing.T) {
		for _, c := range v.Encrypt {
			payload := unhex(t, c.Payload)
			buf := make([]byte, e2eIVLength+len(payload), e2eIVLength+len(payload)+e2eTagLength)
			copy(buf[e2eIVLength:], payload)
			blob, err := sealInPlace(key, iv, buf)
			if err != nil {
				t.Fatal(err)
			}
			if want := unhex(t, c.Blob); !bytes.Equal(blob, want) {
				t.Errorf("%s: ciphertext differs from crypto.js", c.ID)
			}
			pt, err := decryptBlob(key, unhex(t, c.Blob))
			if err != nil || !bytes.Equal(pt, payload) {
				t.Errorf("%s: decrypting crypto.js ciphertext: %v", c.ID, err)
			}
		}
		for _, c := range v.DecryptFails {
			if _, err := decryptBlob(key, unhex(t, c.Blob)); !errors.Is(err, ErrDecryptionFailed) {
				t.Errorf("%s: want ErrDecryptionFailed, got %v", c.ID, err)
			}
		}
	})

	t.Run("share url", func(t *testing.T) {
		for _, c := range v.ShareURL {
			if got := BuildShareURL(c.Base, c.ClaimCode, c.Key); got != c.URL {
				t.Errorf("BuildShareURL(%q) = %q, crypto.js %q", c.Base, got, c.URL)
			}
			link, err := ParseShareURL(c.URL)
			if err != nil {
				t.Errorf("ParseShareURL(%q): %v", c.URL, err)
				continue
			}
			if link.ClaimCode != c.ClaimCode || link.Key != c.Key || BuildShareURL(link.BaseURL, link.ClaimCode, link.Key) != c.URL {
				t.Errorf("ParseShareURL(%q) = %+v", c.URL, link)
			}
		}
	})
}

func TestPadmeMatchesReference(t *testing.T) {
	// Reference from the paper with plain loops, over a dense range.
	ref := func(n int64) int64 {
		if n < 2 {
			return n
		}
		e := int64(0)
		for (int64(1) << (e + 1)) <= n {
			e++
		}
		s := int64(0)
		for x := e; x > 0; x >>= 1 {
			s++
		}
		z := e - s
		if z <= 0 {
			return n
		}
		m := int64(1)<<z - 1
		return (n + m) &^ m
	}
	for n := int64(0); n < 200000; n++ {
		if got, want := padmeLength(n), ref(n); got != want {
			t.Fatalf("padmeLength(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestParseShareURLRejects(t *testing.T) {
	good := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	for _, link := range []string{
		"",
		"ftp://h.example/#/claim/abcdefgh/key/" + good,
		"https://h.example/claim/abcdefgh",
		"https://h.example/#/claim/abcdefgh",
		"https://h.example/#/claim/abc/key/" + good,             // claim code too short
		"https://h.example/#/claim/abcdefgh/key/short",          // key too short
		"https://h.example/#/claim/abcdefgh/key/" + good + "AA", // key too long
		"https://h.example/#/claim/../../x/key/" + good,
		"https:///#/claim/abcdefgh/key/" + good,
	} {
		if _, err := ParseShareURL(link); err == nil {
			t.Errorf("ParseShareURL(%q) accepted", link)
		}
	}
	l, err := ParseShareURL("  https://h.example:8443/base/#/claim/abcdefgh/key/" + good + "=  ")
	if err != nil || l.BaseURL != "https://h.example:8443/base" || l.ClaimCode != "abcdefgh" {
		t.Fatalf("got %+v, %v", l, err)
	}
}

func TestUnwrapDownloadMatchesWebApp(t *testing.T) {
	sf02, _ := wrapPayload("inner.txt", []byte("body"), true, 0)
	sf02NoName, _ := wrapPayload("", []byte("body"), true, 0)
	sf01, _ := wrapPayload("inner.txt", []byte("body"), false, 0)
	badPad := append([]byte(nil), sf02...)
	badPad[len(badPad)-1] = 1

	cases := []struct {
		name, stored, wantName, wantData string
		payload                          []byte
		wantErr                          bool
	}{
		{"hidden sf02", EncryptedFilename, "inner.txt", "body", sf02, false},
		{"hidden sf01", EncryptedFilename, "inner.txt", "body", sf01, false},
		{"hidden sf02 bad padding", EncryptedFilename, "", "", badPad, true},
		{"hidden but raw", EncryptedFilename, EncryptedFilename, "raw", []byte("raw"), false},
		{"visible sf02: server name wins", "visible.txt", "visible.txt", "body", sf02, false},
		{"visible sf02 without name", "visible.txt", "visible.txt", "body", sf02NoName, false},
		{"visible bad sf02 stays raw", "visible.txt", "visible.txt", string(badPad), badPad, false},
		{"visible sf01 is never unwrapped", "visible.txt", "visible.txt", string(sf01), sf01, false},
	}
	for _, c := range cases {
		got, err := unwrapDownload(append([]byte(nil), c.payload...), c.stored)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: want error", c.name)
			}
			continue
		}
		if err != nil || got.Filename != c.wantName || string(got.Data) != c.wantData {
			t.Errorf("%s: got %q %q, %v", c.name, got.Filename, got.Data, err)
		}
	}
}

func TestSafeFilename(t *testing.T) {
	cases := map[string]string{
		"report.pdf":             "report.pdf",
		"../../etc/passwd":       "passwd",
		"..\\..\\boot.ini":       "boot.ini",
		"/abs/path/x.txt":        "x.txt",
		"dir/":                   "fallback",
		"..":                     "fallback",
		"...":                    "fallback",
		".bash_profile":          "bash_profile",
		"..gitconfig":            "gitconfig",
		"CON":                    "_CON",
		"nul.txt":                "_nul.txt",
		"com7":                   "_com7",
		"console.txt":            "console.txt",
		"a.txt:evil":             "a.txt_evil",
		"trail. ":                "trail",
		"invoice\u202etxt.exe":   "invoicetxt.exe",
		"what?<>|*\"":            "what______",
		"":                       "fallback",
		"  spaced.txt  ":         "spaced.txt",
		"bell\x07\nname.txt":     "bellname.txt",
		"bad�name":               "badname",
		"naïve 日本語.txt":          "naïve 日本語.txt",
		strings.Repeat("é", 200): strings.Repeat("é", 127),
	}
	for in, want := range cases {
		if got := SafeFilename(in, "fallback"); got != want {
			t.Errorf("SafeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMetadataFileType(t *testing.T) {
	office := append([]byte("PK\x03\x04"), []byte("....word/document.xml....[Content_Types].XML")...)
	cases := []struct {
		data []byte
		want string
	}{
		{[]byte{0xFF, 0xD8, 0xFF, 0xE0, 0, 0}, "JPEG image"},
		{append(append([]byte(nil), pngSignature...), 0, 0), "PNG image"},
		{office, "Office document"},
		{[]byte("PK\x03\x04 plain zip, no office parts"), ""},
		{append(bytes.Repeat([]byte{' '}, 5000), []byte("%PDF-1.7")...), "PDF"},
		{[]byte("junk ... startxref\n123\n%%EOF\n"), "PDF"},
		{[]byte("hello world"), ""},
		{nil, ""},
	}
	for i, c := range cases {
		if got := metadataFileType(c.data); got != c.want {
			t.Errorf("case %d: got %q, want %q", i, got, c.want)
		}
	}
}

func TestShouldEncrypt(t *testing.T) {
	plain := &PublicConfig{}
	ghost := &PublicConfig{AnonymousMode: true}
	required := &PublicConfig{ClientEncryptionRequired: true}
	check := func(mode EncryptMode, cfg *PublicConfig, want bool, wantErr bool) {
		t.Helper()
		got, err := shouldEncrypt(mode, cfg)
		if (err != nil) != wantErr || got != want {
			t.Errorf("shouldEncrypt(%d, %+v) = %v, %v", mode, cfg, got, err)
		}
	}
	check(EncryptAuto, plain, false, false)
	check(EncryptAuto, ghost, true, false)
	check(EncryptAuto, required, true, false)
	check(EncryptAlways, plain, true, false)
	check(EncryptNever, ghost, false, false)
	check(EncryptNever, required, false, true)
	if _, err := shouldEncrypt(EncryptNever, required); !errors.Is(err, ErrClientEncryptionRequired) {
		t.Errorf("want ErrClientEncryptionRequired, got %v", err)
	}
}

// fakeServer is a minimal SafeShare API for upload/download round trips.
type fakeServer struct {
	cfg map[string]any

	mu          sync.Mutex
	stored      []byte
	storedName  string
	simpleFlags []string // client_encrypted form field + header per simple upload
	initBody    map[string]any
	initHeader  string
	chunkHeader []string
	chunks      map[int][]byte
}

func newFakeServer(t *testing.T, cfg map[string]any) (*fakeServer, *httptest.Server) {
	fs := &fakeServer{cfg: cfg, chunks: map[int][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fs.cfg)
	})
	mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		f, h, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		data, _ := io.ReadAll(f)
		fs.mu.Lock()
		fs.stored, fs.storedName = data, h.Filename
		fs.simpleFlags = append(fs.simpleFlags, r.FormValue("client_encrypted"), r.Header.Get("X-SafeShare-Client-Encrypted"))
		fs.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"claim_code": "Claim1234", "original_filename": h.Filename, "file_size": len(data)})
	})
	mux.HandleFunc("/api/upload/init", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		fs.mu.Lock()
		fs.initBody, fs.initHeader = body, r.Header.Get("X-SafeShare-Client-Encrypted")
		fs.mu.Unlock()
		size := int64(body["total_size"].(float64))
		chunk := int64(1000)
		json.NewEncoder(w).Encode(map[string]any{"upload_id": "0123abcd-0000-4000-8000-000000000000", "chunk_size": chunk, "total_chunks": (size + chunk - 1) / chunk})
	})
	mux.HandleFunc("/api/upload/chunk/", func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(64 << 20)
		f, _, err := r.FormFile("chunk")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		data, _ := io.ReadAll(f)
		var n int
		parts := strings.Split(r.URL.Path, "/")
		json.Unmarshal([]byte(parts[len(parts)-1]), &n)
		fs.mu.Lock()
		fs.chunks[n] = data
		fs.chunkHeader = append(fs.chunkHeader, r.Header.Get("X-SafeShare-Client-Encrypted"))
		fs.mu.Unlock()
		w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/upload/complete/", func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		var all []byte
		for i := 0; i < len(fs.chunks); i++ {
			all = append(all, fs.chunks[i]...)
		}
		fs.stored, fs.storedName = all, fs.initBody["filename"].(string)
		fs.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"claim_code": "Claim1234", "original_filename": fs.storedName, "file_size": len(all)})
	})
	mux.HandleFunc("/api/claim/Claim1234/info", func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"original_filename": fs.storedName, "file_size": len(fs.stored), "download_available": true})
	})
	mux.HandleFunc("/api/claim/Claim1234", func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		w.Write(fs.stored)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return fs, srv
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEncryptedUploadRoundTrip(t *testing.T) {
	ghostCfg := map[string]any{"max_file_size": 1 << 20, "chunked_upload_threshold": 1 << 20, "chunk_size": 1000, "anonymous_mode": true, "strip_metadata": true}
	plainBody := []byte("secret notes for the recipient")

	t.Run("ghost simple upload is padded and hides the name", func(t *testing.T) {
		fs, srv := newFakeServer(t, ghostCfg)
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		res, err := c.Upload(context.Background(), writeTemp(t, "notes.txt", plainBody), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Encrypted || res.ShareURL != BuildShareURL(srv.URL, "Claim1234", res.EncryptionKey) {
			t.Fatalf("result: %+v", res)
		}
		if fs.storedName != EncryptedFilename || bytes.Contains(fs.stored, plainBody) || bytes.Contains(fs.stored, []byte("notes.txt")) {
			t.Fatalf("server saw plaintext or name: %q", fs.storedName)
		}
		if len(fs.stored) != padMinBytes+CiphertextOverhead {
			t.Fatalf("stored %d bytes, want the 4096-byte bucket + overhead", len(fs.stored))
		}
		if strings.Join(fs.simpleFlags, ",") != "true,true" {
			t.Fatalf("client_encrypted flags: %v", fs.simpleFlags)
		}
		key, _ := decodeKey(res.EncryptionKey)
		pt, err := decryptBlob(key, append([]byte(nil), fs.stored...))
		if err != nil || !hasPaddedPayloadMagic(pt) {
			t.Fatalf("stored blob is not SF02: %v", err)
		}
		got, err := c.DownloadDecrypted(context.Background(), "Claim1234", res.EncryptionKey, nil)
		if err != nil || got.Filename != "notes.txt" || !bytes.Equal(got.Data, plainBody) {
			t.Fatalf("download: %+v, %v", got, err)
		}
		dest := filepath.Join(t.TempDir(), "out.txt")
		if err := c.Download(context.Background(), "Claim1234", dest, &DownloadOptions{DecryptionKey: res.EncryptionKey}); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(dest); !bytes.Equal(b, plainBody) {
			t.Fatalf("written file: %q", b)
		}
		if info, _ := os.Stat(dest); info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", info.Mode().Perm())
		}
		if err := c.Download(context.Background(), "Claim1234", dest, &DownloadOptions{DecryptionKey: res.EncryptionKey}); err == nil {
			t.Fatal("overwrote an existing file without Overwrite")
		}
		wrong, _ := GenerateEncryptionKey()
		if _, err := c.DownloadDecrypted(context.Background(), "Claim1234", wrong, nil); !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("wrong key: %v", err)
		}
	})

	t.Run("ghost chunked upload sends the flag at init", func(t *testing.T) {
		cfg := map[string]any{}
		for k, v := range ghostCfg {
			cfg[k] = v
		}
		cfg["chunked_upload_threshold"] = 2000
		fs, srv := newFakeServer(t, cfg)
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		body := bytes.Repeat([]byte("0123456789"), 900) // 9000 bytes -> 9216-byte bucket
		res, err := c.Upload(context.Background(), writeTemp(t, "big.log", body), &UploadOptions{ShowFilename: true})
		if err != nil {
			t.Fatal(err)
		}
		if fs.initBody["client_encrypted"] != true || fs.initHeader != "true" || fs.initBody["filename"] != "big.log" {
			t.Fatalf("init: %v header %q", fs.initBody, fs.initHeader)
		}
		if len(fs.stored) != int(padmeLength(v2FixedHeader+9000))+CiphertextOverhead || len(fs.chunks) < 2 {
			t.Fatalf("stored %d bytes in %d chunks", len(fs.stored), len(fs.chunks))
		}
		got, err := c.DownloadDecrypted(context.Background(), "Claim1234", res.EncryptionKey, nil)
		if err != nil || got.Filename != "big.log" || !bytes.Equal(got.Data, body) {
			t.Fatalf("download: %v", err)
		}
	})

	t.Run("required server, not ghost: still padded", func(t *testing.T) {
		fs, srv := newFakeServer(t, map[string]any{"max_file_size": 1 << 20, "chunked_upload_threshold": 1 << 20, "client_encryption_required": true})
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		res, err := c.Upload(context.Background(), writeTemp(t, "a.txt", plainBody), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs.stored) != padMinBytes+CiphertextOverhead {
			t.Fatalf("stored %d, want the padded 4096-byte bucket + overhead", len(fs.stored))
		}
		if _, err := c.Upload(context.Background(), writeTemp(t, "b.txt", plainBody), &UploadOptions{Encrypt: EncryptNever}); !errors.Is(err, ErrClientEncryptionRequired) {
			t.Fatalf("EncryptNever against a required server: %v", err)
		}
		got, err := c.DownloadDecrypted(context.Background(), "Claim1234", res.EncryptionKey, nil)
		if err != nil || got.Filename != "a.txt" {
			t.Fatalf("download: %+v %v", got, err)
		}
	})

	t.Run("plain server: auto stays unencrypted", func(t *testing.T) {
		fs, srv := newFakeServer(t, map[string]any{"max_file_size": 1 << 20, "chunked_upload_threshold": 1 << 20})
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		res, err := c.Upload(context.Background(), writeTemp(t, "a.txt", plainBody), nil)
		if err != nil || res.Encrypted || res.ShareURL != "" || !bytes.Equal(fs.stored, plainBody) || fs.simpleFlags[1] != "" {
			t.Fatalf("got %+v, %v, stored %q", res, err, fs.stored)
		}
	})

	t.Run("ghost refuses files it would have cleaned", func(t *testing.T) {
		fs, srv := newFakeServer(t, ghostCfg)
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		jpeg := writeTemp(t, "photo.jpg", []byte{0xFF, 0xD8, 0xFF, 0xE1, 'E', 'x', 'i', 'f'})
		if _, err := c.Upload(context.Background(), jpeg, nil); !errors.Is(err, ErrMetadataNotRemoved) {
			t.Fatalf("want ErrMetadataNotRemoved, got %v", err)
		}
		if fs.stored != nil {
			t.Fatal("refused file reached the server")
		}
		res, err := c.Upload(context.Background(), jpeg, &UploadOptions{KeepMetadata: true})
		if err != nil || res.MetadataKept != "JPEG image" {
			t.Fatalf("KeepMetadata: %+v, %v", res, err)
		}
	})

	t.Run("too large once encrypted", func(t *testing.T) {
		_, srv := newFakeServer(t, map[string]any{"max_file_size": 100, "chunked_upload_threshold": 1 << 20, "anonymous_mode": true})
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		if _, err := c.Upload(context.Background(), writeTemp(t, "x.txt", make([]byte, 80)), nil); !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("want ErrPayloadTooLarge, got %v", err)
		}
	})
}

func TestDownloadDecryptedRefusesOversizedBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/claim/Claim1234/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"original_filename":"encrypted.bin","file_size":10}`))
	})
	mux.HandleFunc("/api/claim/Claim1234", func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush() // chunked: no Content-Length
		w.Write(make([]byte, 5000))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
	key, _ := GenerateEncryptionKey()
	if _, err := c.DownloadDecrypted(context.Background(), "Claim1234", key, nil); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("want size error, got %v", err)
	}
}

// TestClientUsesSOCKSProxyWithRemoteDNS checks that HTTPS_PROXY=socks5://...
// routes requests through the proxy and hands it the host name unresolved,
// so a Tor user's DNS lookups don't leak. Go reads the proxy variables once
// per process, so the client runs in a child test process started with them.
func TestClientUsesSOCKSProxyWithRemoteDNS(t *testing.T) {
	if os.Getenv("SAFESHARE_PROXY_TEST_CHILD") == "1" {
		c, err := NewClient(ClientConfig{BaseURL: "http://exampleonionaddressxyz.onion"})
		if err != nil {
			t.Fatal(err)
		}
		c.GetConfig(context.Background()) // fails at the proxy; the parent checks what it was asked
		return
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- "no connection: " + err.Error()
			return
		}
		defer conn.Close()
		buf := make([]byte, 512)
		// Greeting: VER NMETHODS METHODS...
		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			got <- "bad greeting"
			return
		}
		io.ReadFull(conn, buf[:buf[1]])
		conn.Write([]byte{5, 0})
		// Request: VER CMD RSV ATYP ADDR PORT
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			got <- "bad request"
			return
		}
		if buf[3] != 3 { // 3 = domain name; 1 and 4 would mean it resolved locally
			got <- fmt.Sprintf("address type %d", buf[3])
			return
		}
		io.ReadFull(conn, buf[:1])
		n := int(buf[0])
		io.ReadFull(conn, buf[:n+2])
		got <- fmt.Sprintf("%s:%d", buf[:n], binary.BigEndian.Uint16(buf[n:n+2]))
		conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}) // general failure
	}()

	proxy := "socks5://" + ln.Addr().String()
	cmd := exec.Command(os.Args[0], "-test.run=^TestClientUsesSOCKSProxyWithRemoteDNS$")
	// Only HTTPS_PROXY, with an http:// .onion URL: Go's per-scheme rules would
	// connect directly; a single configured proxy must cover every request.
	cmd.Env = append(os.Environ(), "SAFESHARE_PROXY_TEST_CHILD=1", "HTTPS_PROXY="+proxy, "HTTP_PROXY=", "http_proxy=", "ALL_PROXY=", "all_proxy=", "NO_PROXY=", "no_proxy=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	select {
	case addr := <-got:
		if addr != "exampleonionaddressxyz.onion:80" {
			t.Fatalf("proxy was asked for %q, want the unresolved host name", addr)
		}
	default:
		t.Fatal("the request did not go through the proxy")
	}
}

func TestSealInPlaceNeedsTagCapacity(t *testing.T) {
	key := make([]byte, e2eKeyLength)
	iv := make([]byte, e2eIVLength)
	if _, err := sealInPlace(key, iv, make([]byte, 40)); err == nil {
		t.Fatal("accepted a buffer without room for the tag")
	}
	if _, err := sealInPlace(key, iv[:8], make([]byte, 40, 56)); err == nil {
		t.Fatal("accepted a short IV")
	}
}

func TestReadExactlyDetectsChangedFile(t *testing.T) {
	p := writeTemp(t, "f", []byte("0123456789"))
	if err := readExactly(p, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if err := readExactly(p, make([]byte, 9)); err == nil {
		t.Fatal("file that grew was accepted")
	}
	if err := readExactly(p, make([]byte, 11)); err == nil {
		t.Fatal("file that shrank was accepted")
	}
}

func TestEncryptedEdgeCases(t *testing.T) {
	plainCfg := map[string]any{"max_file_size": 1 << 20, "chunked_upload_threshold": 1 << 20}

	t.Run("empty file, name visible, not ghost: padded", func(t *testing.T) {
		fs, srv := newFakeServer(t, plainCfg)
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		res, err := c.Upload(context.Background(), writeTemp(t, "empty.txt", nil), &UploadOptions{Encrypt: EncryptAlways, ShowFilename: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(fs.stored) != padMinBytes+CiphertextOverhead || fs.storedName != "empty.txt" || res.Filename != "empty.txt" {
			t.Fatalf("stored %d bytes as %q", len(fs.stored), fs.storedName)
		}
		var buf bytes.Buffer
		if err := c.DownloadToWriter(context.Background(), "Claim1234", &buf, &DownloadOptions{DecryptionKey: res.EncryptionKey}); err != nil || buf.Len() != 0 {
			t.Fatalf("DownloadToWriter: %v, %d bytes", err, buf.Len())
		}
	})

	t.Run("hidden name is reported, not encrypted.bin", func(t *testing.T) {
		_, srv := newFakeServer(t, plainCfg)
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		res, err := c.Upload(context.Background(), writeTemp(t, "real.txt", []byte("x")), &UploadOptions{Encrypt: EncryptAlways})
		if err != nil || res.Filename != "real.txt" {
			t.Fatalf("%+v, %v", res, err)
		}
	})

	t.Run("existing destination is refused before downloading", func(t *testing.T) {
		var downloads int
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { downloads++ })
		srv := httptest.NewServer(mux)
		defer srv.Close()
		c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
		key, _ := GenerateEncryptionKey()
		dest := writeTemp(t, "exists.txt", []byte("keep me"))
		err := c.Download(context.Background(), "Claim1234", dest, &DownloadOptions{DecryptionKey: key})
		if !errors.Is(err, ErrDestinationExists) || downloads != 0 {
			t.Fatalf("err %v after %d requests", err, downloads)
		}
		link := filepath.Join(t.TempDir(), "link")
		os.Symlink(dest, link)
		if err := CheckDestination(link, true); err == nil {
			t.Fatal("symlink accepted with overwrite")
		}
	})

	t.Run("share link with query and odd fragments", func(t *testing.T) {
		good := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
		l, err := ParseShareURL("https://h.example/?utm=1#/claim/abcdefgh/key/" + good)
		if err != nil || l.BaseURL != "https://h.example" {
			t.Fatalf("query: %+v %v", l, err)
		}
		if _, err := ParseShareURL("https://h.example/#/claim/abcdefgh/key/" + good + "#/claim/x"); err == nil {
			t.Fatal("double fragment accepted")
		}
	})
}

func TestRedirectsStayOnOrigin(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/config", http.StatusFound)
	}))
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL, APIToken: "safeshare_secret"})
	if _, err := c.GetConfig(context.Background()); err == nil || !strings.Contains(err.Error(), "refusing redirect") {
		t.Fatalf("want refused redirect, got %v", err)
	}
	if hits != 0 {
		t.Fatal("followed a redirect to another origin")
	}
}

func TestProxyConfig(t *testing.T) {
	for _, bad := range []string{"ftp://x:1", "not a url", "socks5://"} {
		if _, err := NewClient(ClientConfig{BaseURL: "https://h.example", Proxy: bad}); err == nil {
			t.Errorf("proxy %q accepted", bad)
		}
	}
	c, err := NewClient(ClientConfig{BaseURL: "http://127.0.0.1:1", Proxy: "socks5h://127.0.0.1:9050"})
	if err != nil {
		t.Fatal(err)
	}
	tr := c.httpClient.Transport.(*http.Transport)
	for _, target := range []string{"http://127.0.0.1:1/x", "https://h.example/x", "http://abc.onion/x"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		u, err := tr.Proxy(req)
		if err != nil || u == nil || u.String() != "socks5://127.0.0.1:9050" {
			t.Errorf("%s: proxy %v, %v (want the configured proxy, loopback included)", target, u, err)
		}
	}
	c, _ = NewClient(ClientConfig{BaseURL: "https://h.example", DisableProxy: true})
	if c.httpClient.Transport.(*http.Transport).Proxy != nil {
		t.Error("DisableProxy left a proxy set")
	}
}

func TestDownloadDecryptedRefusesHugeReportedSize(t *testing.T) {
	var downloads int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/claim/Claim1234/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"original_filename":"encrypted.bin","file_size":4611686018427387904}`))
	})
	mux.HandleFunc("/api/claim/Claim1234", func(w http.ResponseWriter, r *http.Request) { downloads++ })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
	key, _ := GenerateEncryptionKey()
	if _, err := c.DownloadDecrypted(context.Background(), "Claim1234", key, nil); !errors.Is(err, ErrFileTooLarge) || downloads != 0 {
		t.Fatalf("got %v after %d downloads", err, downloads)
	}
}

func TestEncryptAlwaysIgnoresServerMode(t *testing.T) {
	// A server reporting it isn't in Ghost mode still gets ciphertext, padded,
	// under EncryptAlways (the CLI's default over Tor or a proxy).
	fs, srv := newFakeServer(t, map[string]any{"max_file_size": 1 << 20, "chunked_upload_threshold": 1 << 20})
	c, _ := NewClient(ClientConfig{BaseURL: srv.URL})
	body := []byte("do not reveal")
	if _, err := c.Upload(context.Background(), writeTemp(t, "s.txt", body), &UploadOptions{Encrypt: EncryptAlways}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(fs.stored, body) || len(fs.stored) != padMinBytes+CiphertextOverhead {
		t.Fatalf("stored %d bytes, plaintext visible: %v", len(fs.stored), bytes.Contains(fs.stored, body))
	}
}

func TestOverwriteReplacesSymlinkInsteadOfFollowing(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("original"), 0o600)
	dest := filepath.Join(dir, "dest")
	os.Symlink(victim, dest) // swapped in after the destination check
	if err := replaceFile(dest, []byte("newer")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "original" {
		t.Fatalf("followed the symlink: victim now %q", b)
	}
	if info, _ := os.Lstat(dest); info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("dest is still a symlink")
	}
}
