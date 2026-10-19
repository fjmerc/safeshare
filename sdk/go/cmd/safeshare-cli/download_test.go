package main

import (
	"archive/tar"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"filippo.io/age"
)

func TestDownloadDropWithIdentity(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	tw := tar.NewWriter(&plain)
	tw.WriteHeader(&tar.Header{Name: "message.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("hi"))
	tw.Close()
	var blob bytes.Buffer
	w, _ := age.Encrypt(&blob, id.Recipient())
	w.Write(plain.Bytes())
	w.Close()

	var downloads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/claim/drop1234/info":
			w.Write([]byte(`{"claim_code":"drop1234","original_filename":"safeshare-drop.tar.age","file_size":1}`))
		case "/api/claim/plain123/info":
			w.Write([]byte(`{"claim_code":"plain123","original_filename":"report.pdf","file_size":1}`))
		default:
			downloads.Add(1)
			w.Write(blob.Bytes())
		}
	}))
	defer srv.Close()
	oldURL := baseURL
	baseURL = srv.URL
	defer func() { baseURL = oldURL }()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "drop-key.txt")
	if err := os.WriteFile(keyPath, []byte("# public key: "+id.Recipient().String()+"\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")

	run := func(args ...string) error {
		cmd := downloadCmd()
		cmd.SetArgs(args)
		cmd.SetOut(&bytes.Buffer{})
		return cmd.Execute()
	}
	if err := run("drop1234", out, "--identity", keyPath, "--no-progress"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "message.txt")); string(got) != "hi" {
		t.Fatalf("message.txt = %q", got)
	}

	// A bad key file is reported without its contents.
	badKey := filepath.Join(dir, "bad.txt")
	secret := "AGE-SECRET-KEY-1NOTAREALKEYBUTSECRETLOOKING"
	os.WriteFile(badKey, []byte(secret+"\n"), 0o600)
	err = run("drop1234", filepath.Join(dir, "out2"), "--identity", badKey, "--no-progress")
	if err == nil || strings.Contains(err.Error(), "NOTAREALKEY") {
		t.Fatalf("err = %v", err)
	}
	// age's own error for a key with one wrong character quotes part of it.
	real := id.String()
	corrupt := real[:len(real)-3] + "B" + real[len(real)-2:]
	if corrupt == real {
		corrupt = real[:len(real)-3] + "C" + real[len(real)-2:]
	}
	os.WriteFile(badKey, []byte(corrupt+"\n"), 0o600)
	err = run("drop1234", filepath.Join(dir, "out2"), "--identity", badKey, "--no-progress")
	if err == nil || strings.Contains(err.Error(), "s[") || strings.Contains(err.Error(), corrupt[16:24]) {
		t.Fatalf("err = %v", err)
	}
	if err := run("drop1234", filepath.Join(dir, "out2"), "--identity", filepath.Join(dir, "missing.txt")); err == nil {
		t.Fatal("missing key file accepted")
	}

	// A code that isn't a drop is refused before downloading.
	before := downloads.Load()
	if err := run("plain123", filepath.Join(dir, "out3"), "--identity", keyPath); err == nil || !strings.Contains(err.Error(), "not a drop-page submission") {
		t.Fatalf("plain file: err = %v", err)
	}
	if downloads.Load() != before {
		t.Fatal("downloaded a file that isn't a drop")
	}

	// The default directory is drop-CODE in the current directory.
	t.Chdir(dir)
	if err := run("drop1234", "--identity", keyPath, "--no-progress"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "drop-drop1234", "message.txt")); string(got) != "hi" {
		t.Fatalf("default dir message.txt = %q", got)
	}

	if err := run("https://host/#/claim/drop1234/key/abc", "--identity", keyPath); err == nil || !strings.Contains(err.Error(), "claim code") {
		t.Fatalf("share link with --identity: err = %v", err)
	}
	if err := run("drop1234", out, "--identity", keyPath); err == nil || !strings.Contains(err.Error(), "already exists; give a directory") {
		t.Fatalf("existing destination: err = %v", err)
	}
}
