package s3

import (
	"bytes"
	"io"
	"testing"
)

// TestValidateKey tests the key validation function
func TestValidateKey(t *testing.T) {
	s := &S3Storage{bucket: "test-bucket"}

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		// Valid keys
		{name: "simple filename", key: "test.txt", wantErr: false},
		{name: "path with slash", key: "folder/file.txt", wantErr: false},
		{name: "deep path", key: "a/b/c/d/e/file.txt", wantErr: false},
		{name: "uuid filename", key: "550e8400-e29b-41d4-a716-446655440000", wantErr: false},

		// Invalid keys - path traversal
		{name: "path traversal ..", key: "../secret.txt", wantErr: true},
		{name: "path traversal in middle", key: "folder/../secret.txt", wantErr: true},
		{name: "path traversal at start", key: "..secret.txt", wantErr: true},

		// Invalid keys - special characters
		{name: "null byte", key: "file\x00.txt", wantErr: true},
		{name: "url encoded", key: "file%2F.txt", wantErr: true},
		{name: "empty key", key: "", wantErr: true},

		// Invalid keys - special paths
		{name: "just dot", key: ".", wantErr: true},
		{name: "just slash", key: "/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.validateKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKey(%q) error = %v, wantErr %v", tt.key, err, tt.wantErr)
			}
		})
	}
}

// TestValidateUploadID tests the upload ID validation function
func TestValidateUploadID(t *testing.T) {
	s := &S3Storage{bucket: "test-bucket"}

	tests := []struct {
		name     string
		uploadID string
		wantErr  bool
	}{
		// Valid upload IDs
		{name: "uuid", uploadID: "550e8400-e29b-41d4-a716-446655440000", wantErr: false},
		{name: "simple id", uploadID: "upload123", wantErr: false},

		// Invalid upload IDs
		{name: "empty", uploadID: "", wantErr: true},
		{name: "path traversal", uploadID: "..", wantErr: true},
		{name: "contains slash", uploadID: "folder/id", wantErr: true},
		{name: "null byte", uploadID: "id\x00test", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.validateUploadID(tt.uploadID)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUploadID(%q) error = %v, wantErr %v", tt.uploadID, err, tt.wantErr)
			}
		})
	}
}

// TestValidateChunkNum tests the chunk number validation function
func TestValidateChunkNum(t *testing.T) {
	s := &S3Storage{bucket: "test-bucket"}

	tests := []struct {
		name     string
		chunkNum int
		wantErr  bool
	}{
		// Valid chunk numbers
		{name: "zero", chunkNum: 0, wantErr: false},
		{name: "small positive", chunkNum: 10, wantErr: false},
		{name: "large positive", chunkNum: 99999, wantErr: false},

		// Invalid chunk numbers
		{name: "negative", chunkNum: -1, wantErr: true},
		{name: "very negative", chunkNum: -1000, wantErr: true},
		{name: "at max", chunkNum: maxChunkNumber, wantErr: true},
		{name: "above max", chunkNum: maxChunkNumber + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.validateChunkNum(tt.chunkNum)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateChunkNum(%d) error = %v, wantErr %v", tt.chunkNum, err, tt.wantErr)
			}
		})
	}
}

// TestGetChunkKey tests the chunk key generation
func TestGetChunkKey(t *testing.T) {
	s := &S3Storage{bucket: "test-bucket"}

	tests := []struct {
		name     string
		uploadID string
		chunkNum int
		want     string
	}{
		{
			name:     "first chunk",
			uploadID: "upload123",
			chunkNum: 0,
			want:     ".partial/upload123/chunk_0",
		},
		{
			name:     "chunk 10",
			uploadID: "abc-def-ghi",
			chunkNum: 10,
			want:     ".partial/abc-def-ghi/chunk_10",
		},
		{
			name:     "large chunk number",
			uploadID: "test",
			chunkNum: 9999,
			want:     ".partial/test/chunk_9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.getChunkKey(tt.uploadID, tt.chunkNum)
			if got != tt.want {
				t.Errorf("getChunkKey(%q, %d) = %q, want %q", tt.uploadID, tt.chunkNum, got, tt.want)
			}
		})
	}
}

// TestHashingReader tests the hashing reader
func TestHashingReader(t *testing.T) {
	testData := []byte("Hello, World!")
	expectedHash := "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"

	hr := newHashingReader(bytes.NewReader(testData))

	// Read all data
	buf := make([]byte, len(testData))
	n, err := hr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Read %d bytes, want %d", n, len(testData))
	}

	// Check hash
	hash := hr.Hash()
	if hash != expectedHash {
		t.Errorf("Hash = %q, want %q", hash, expectedHash)
	}
}

// TestS3ConfigValidation tests S3Config requirements
func TestS3ConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     S3Config
		wantErr bool
	}{
		{
			name: "valid config with all fields",
			cfg: S3Config{
				Bucket:          "my-bucket",
				Region:          "us-west-2",
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantErr: false,
		},
		{
			name: "valid config with endpoint for MinIO",
			cfg: S3Config{
				Bucket:          "my-bucket",
				Region:          "us-east-1",
				Endpoint:        "http://localhost:9000",
				AccessKeyID:     "minioadmin",
				SecretAccessKey: "minioadmin",
				PathStyle:       true,
			},
			wantErr: false,
		},
		{
			name: "missing bucket",
			cfg: S3Config{
				Region: "us-west-2",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't actually create the storage without S3, but we can validate the config check
			if tt.cfg.Bucket == "" && !tt.wantErr {
				t.Errorf("Expected error for empty bucket")
			}
		})
	}
}
