package utils

import (
	"errors"
	"os"
	"testing"
)

func writeTempChunk(t *testing.T, dir, uploadID string, data string) string {
	t.Helper()
	if err := os.MkdirAll(GetUploadChunksDir(dir, uploadID), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(GetUploadChunksDir(dir, uploadID), "tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

// T51: a first write must never replace a chunk another request stored.
func TestCommitNewChunk(t *testing.T) {
	dir := t.TempDir()
	const id = "550e8400-e29b-41d4-a716-446655440051"
	final := GetChunkPath(dir, id, 0)

	first := writeTempChunk(t, dir, id, "first")
	if err := CommitNewChunk(first, dir, id, 0); err != nil {
		t.Fatalf("first CommitNewChunk = %v", err)
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Errorf("temp file still present after commit: %v", err)
	}

	second := writeTempChunk(t, dir, id, "second")
	if err := CommitNewChunk(second, dir, id, 0); !errors.Is(err, ErrChunkAlreadyStored) {
		t.Fatalf("second CommitNewChunk = %v, want ErrChunkAlreadyStored", err)
	}
	if got, _ := os.ReadFile(final); string(got) != "first" {
		t.Errorf("stored chunk = %q, want %q (first write wins)", got, "first")
	}
	if _, err := os.Stat(second); err != nil {
		t.Errorf("losing temp file should be left for the caller to remove: %v", err)
	}

	// CommitChunk still replaces (used only for wrong-size leftovers).
	if err := CommitChunk(second, dir, id, 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(final); string(got) != "second" {
		t.Errorf("after CommitChunk stored = %q, want %q", got, "second")
	}
}
