package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/database"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestMigrationTool(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")

	// Create uploads directory
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("Failed to create uploads directory: %v", err)
	}

	// Initialize database
	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create test files
	tests := []struct {
		name            string
		data            []byte
		encrypted       bool
		useLegacy       bool
		expectedMigrate bool
	}{
		{
			name:            "legacy_encrypted_file",
			data:            []byte("This is a test file for legacy encryption"),
			encrypted:       true,
			useLegacy:       true,
			expectedMigrate: true,
		},
		{
			name:            "sfse1_encrypted_file",
			data:            []byte("This is a test file for SFSE1 encryption"),
			encrypted:       true,
			useLegacy:       false,
			expectedMigrate: false,
		},
		{
			name:            "unencrypted_file",
			data:            []byte("This is an unencrypted test file"),
			encrypted:       false,
			useLegacy:       false,
			expectedMigrate: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storedFilename := tt.name + ".dat"
			filePath := filepath.Join(uploadsDir, storedFilename)

			// Create file based on encryption type
			if tt.encrypted {
				if tt.useLegacy {
					// Create legacy encrypted file
					encrypted, err := utils.EncryptFile(tt.data, testKey)
					if err != nil {
						t.Fatalf("Failed to encrypt file: %v", err)
					}
					if err := os.WriteFile(filePath, encrypted, 0600); err != nil {
						t.Fatalf("Failed to write encrypted file: %v", err)
					}
				} else {
					// Create SFSE1 encrypted file
					tempPlainPath := filePath + ".plain"
					if err := os.WriteFile(tempPlainPath, tt.data, 0600); err != nil {
						t.Fatalf("Failed to write temp plaintext: %v", err)
					}
					if err := utils.EncryptFileStreaming(tempPlainPath, filePath, testKey); err != nil {
						t.Fatalf("Failed to encrypt file with SFSE1: %v", err)
					}
					os.Remove(tempPlainPath)
				}
			} else {
				// Create unencrypted file
				if err := os.WriteFile(filePath, tt.data, 0600); err != nil {
					t.Fatalf("Failed to write unencrypted file: %v", err)
				}
			}

			// Add file to database
			fileRecord := &models.File{
				ClaimCode:        "test_claim_" + tt.name,
				OriginalFilename: tt.name + ".txt",
				StoredFilename:   storedFilename,
				FileSize:         int64(len(tt.data)),
				MimeType:         "text/plain",
			}
			if err := database.CreateFile(db, fileRecord); err != nil {
				t.Fatalf("Failed to create file record: %v", err)
			}
		})
	}

	// Run migration
	t.Run("migration", func(t *testing.T) {
		err := migrateEncryption(db, uploadsDir, testKey, false)
		if err != nil {
			t.Fatalf("Migration failed: %v", err)
		}
	})

	// Verify results
	for _, tt := range tests {
		t.Run("verify_"+tt.name, func(t *testing.T) {
			storedFilename := tt.name + ".dat"
			filePath := filepath.Join(uploadsDir, storedFilename)

			// Check if file is SFSE-magic (SFSE1 and SFSE2 share the same
			// 5-byte magic; the version byte tells them apart, which
			// IsStreamEncrypted deliberately doesn't need to know).
			isStreamEnc, err := utils.IsStreamEncrypted(filePath)
			if err != nil {
				t.Fatalf("Failed to check encryption format: %v", err)
			}

			if tt.expectedMigrate {
				// Should be SFSE2 now (master finding #10: legacy files are
				// migrated straight to SFSE2, never SFSE1).
				if !isStreamEnc {
					t.Errorf("Expected file to be SFSE-encrypted after migration, but it's not")
				}
				ver, err := utils.PeekSFSEVersion(filePath)
				if err != nil {
					t.Fatalf("PeekSFSEVersion: %v", err)
				}
				if ver != utils.StreamEncryptionVersionV2 {
					t.Fatalf("migrated file SFSE version = 0x%02x, want SFSE2 (0x%02x)", ver, utils.StreamEncryptionVersionV2)
				}

				// The DB row must carry a fresh 16-byte enc_file_id and a
				// sha256_hash (this tool's test fixtures never set one, so
				// this also exercises the "compute and store when empty"
				// requirement).
				rows, err := listFilesForVerify(db, true)
				if err != nil {
					t.Fatalf("listFilesForVerify: %v", err)
				}
				var row verifyFileRow
				found := false
				for _, r := range rows {
					if r.StoredFilename == storedFilename {
						row, found = r, true
						break
					}
				}
				if !found {
					t.Fatalf("no files row for %s", storedFilename)
				}
				if len(row.EncFileID) != utils.SFSE2EncFileIDSize {
					t.Fatalf("enc_file_id length = %d, want %d", len(row.EncFileID), utils.SFSE2EncFileIDSize)
				}
				if row.SHA256Hash == "" {
					t.Error("sha256_hash not populated by migration")
				}

				// Verify it decrypts correctly via the version-aware
				// dispatcher with the DB-sourced enc_file_id.
				tempDecPath := filePath + ".dec"
				if err := utils.DecryptFileStreamingAny(filePath, tempDecPath, testKey, row.EncFileID, row.SHA256Hash, row.FileSize); err != nil {
					t.Fatalf("Failed to decrypt migrated file: %v", err)
				}
				decrypted, err := os.ReadFile(tempDecPath)
				if err != nil {
					t.Fatalf("Failed to read decrypted file: %v", err)
				}
				os.Remove(tempDecPath)

				// Verify data matches original
				if string(decrypted) != string(tt.data) {
					t.Errorf("Decrypted data doesn't match original.\nExpected: %s\nGot: %s", string(tt.data), string(decrypted))
				}
			} else {
				// Should remain in original format
				if tt.encrypted && !tt.useLegacy {
					// Should still be SFSE1 (an already-SFSE file is not this
					// tool's job to touch — that's --upgrade-format's job)
					if !isStreamEnc {
						t.Errorf("SFSE1 file should remain SFSE-encrypted")
					}
					ver, err := utils.PeekSFSEVersion(filePath)
					if err != nil {
						t.Fatalf("PeekSFSEVersion: %v", err)
					}
					if ver != utils.StreamEncryptionVersion {
						t.Errorf("untouched file SFSE version = 0x%02x, want SFSE1 (0x%02x) — migrateEncryption must not touch already-SFSE files", ver, utils.StreamEncryptionVersion)
					}
				} else if !tt.encrypted {
					// Should still be unencrypted
					if isStreamEnc {
						t.Errorf("Unencrypted file should remain unencrypted")
					}
				}
			}
		})
	}
}

func TestMigrationToolDryRun(t *testing.T) {
	// Create temporary directory for test
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")

	// Create uploads directory
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("Failed to create uploads directory: %v", err)
	}

	// Initialize database
	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create legacy encrypted file
	testData := []byte("Test data for dry run")
	encrypted, err := utils.EncryptFile(testData, testKey)
	if err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	storedFilename := "dryrun_test.dat"
	filePath := filepath.Join(uploadsDir, storedFilename)
	if err := os.WriteFile(filePath, encrypted, 0600); err != nil {
		t.Fatalf("Failed to write encrypted file: %v", err)
	}

	// Add file to database
	fileRecord := &models.File{
		ClaimCode:        "test_claim_dryrun",
		OriginalFilename: "dryrun_test.txt",
		StoredFilename:   storedFilename,
		FileSize:         int64(len(testData)),
		MimeType:         "text/plain",
	}
	if err := database.CreateFile(db, fileRecord); err != nil {
		t.Fatalf("Failed to create file record: %v", err)
	}

	// Run migration in dry-run mode
	err = migrateEncryption(db, uploadsDir, testKey, true)
	if err != nil {
		t.Fatalf("Dry-run migration failed: %v", err)
	}

	// Verify file is still legacy encrypted (not migrated)
	isStreamEnc, err := utils.IsStreamEncrypted(filePath)
	if err != nil {
		t.Fatalf("Failed to check encryption format: %v", err)
	}

	if isStreamEnc {
		t.Errorf("Dry-run should not migrate files, but file was migrated")
	}

	// Verify file is still legacy encrypted
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if !utils.IsEncrypted(fileData) {
		t.Errorf("File should still be legacy encrypted after dry-run")
	}
}

// newLegacyFixture writes one legacy (pre-SFSE, single-shot AES-256-GCM)
// encrypted file to uploadsDir and its matching files row to db, returning
// the on-disk path and the row's id.
func newLegacyFixture(t *testing.T, uploadsDir string, db *sql.DB, claimCode string, plaintext []byte, sha256Hash string) (filePath string, fileID int64) {
	t.Helper()
	storedFilename := claimCode + ".dat"
	filePath = filepath.Join(uploadsDir, storedFilename)

	encrypted, err := utils.EncryptFile(plaintext, testKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	if err := os.WriteFile(filePath, encrypted, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fileRecord := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: storedFilename,
		StoredFilename:   storedFilename,
		FileSize:         int64(len(plaintext)),
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		SHA256Hash:       sha256Hash,
	}
	if err := database.CreateFile(db, fileRecord); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	return filePath, fileRecord.ID
}

// TestMigrateEncryption_LegacyFileSizeMismatchFailsClosed is the regression
// test for the LOW finding that the legacy migration path never checked the
// decrypted plaintext against the DB row before committing. A files.file_size
// that doesn't match the actual decrypted length must fail that file, not
// silently migrate a file whose header/DB record then lies about its own
// content.
func TestMigrateEncryption_LegacyFileSizeMismatchFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	plaintext := []byte("the real plaintext, twenty bytes shorter than what the row claims")
	filePath, _ := newLegacyFixture(t, uploadsDir, db, "sizemismatch", plaintext, "")

	// Corrupt the DB row's file_size to not match the actual plaintext.
	if _, err := db.Exec(`UPDATE files SET file_size = file_size + 1000 WHERE claim_code = ?`, "sizemismatch"); err != nil {
		t.Fatalf("corrupt file_size: %v", err)
	}

	if err := migrateEncryption(db, uploadsDir, testKey, false); err == nil {
		t.Fatal("migrateEncryption succeeded despite a plaintext-length mismatch, want error")
	}

	// The file must NOT have been migrated — still legacy format.
	isStreamEnc, err := utils.IsStreamEncrypted(filePath)
	if err != nil {
		t.Fatalf("IsStreamEncrypted: %v", err)
	}
	if isStreamEnc {
		t.Error("file was migrated to SFSE2 despite a plaintext-length mismatch")
	}
}

// TestMigrateEncryption_LegacyFileHashMismatchFailsClosed is the same
// regression test for the sha256_hash half of the check: a files row with
// a hash that doesn't match the actual decrypted plaintext must also fail
// closed rather than migrate.
func TestMigrateEncryption_LegacyFileHashMismatchFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	plaintext := []byte("plaintext that does not match the seeded wrong hash below")
	const wrongHash = "deadbeef00000000000000000000000000000000000000000000000000000000"
	filePath, _ := newLegacyFixture(t, uploadsDir, db, "hashmismatch", plaintext, wrongHash)

	if err := migrateEncryption(db, uploadsDir, testKey, false); err == nil {
		t.Fatal("migrateEncryption succeeded despite a sha256_hash mismatch, want error")
	}

	isStreamEnc, err := utils.IsStreamEncrypted(filePath)
	if err != nil {
		t.Fatalf("IsStreamEncrypted: %v", err)
	}
	if isStreamEnc {
		t.Error("file was migrated to SFSE2 despite a sha256_hash mismatch")
	}
}

// TestMigrateEncryption_PreservesFileMode is the regression test for the
// MEDIUM finding that a migrated legacy file must keep the original file's
// permission mode.
func TestMigrateEncryption_PreservesFileMode(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	plaintext := []byte("legacy file whose mode must survive migration to SFSE2")
	filePath, _ := newLegacyFixture(t, uploadsDir, db, "modecheck", plaintext, "")

	const wantMode = 0640
	if err := os.Chmod(filePath, wantMode); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if err := migrateEncryption(db, uploadsDir, testKey, false); err != nil {
		t.Fatalf("migrateEncryption: %v", err)
	}

	fi, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != os.FileMode(wantMode) {
		t.Errorf("mode after migration = %o, want %o (original mode was not preserved)", got, wantMode)
	}
}

// TestMigrateEncryption_RejectsInvalidStoredFilename is the regression test
// for the LOW finding that files.stored_filename was never validated
// before being joined into a filesystem path.
func TestMigrateEncryption_RejectsInvalidStoredFilename(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	uploadsDir := filepath.Join(tmpDir, "uploads")
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	db, err := database.Initialize(dbPath)
	if err != nil {
		t.Fatalf("database.Initialize: %v", err)
	}
	defer db.Close()

	fileRecord := &models.File{
		ClaimCode:        "badname",
		OriginalFilename: "whatever.txt",
		StoredFilename:   "../../../etc/passwd",
		FileSize:         10,
		MimeType:         "application/octet-stream",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
	if err := database.CreateFile(db, fileRecord); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	// migrateEncryption logs per-file failures rather than returning them
	// individually, but must count this row as failed rather than crash or
	// attempt to touch the traversal path.
	if err := migrateEncryption(db, uploadsDir, testKey, false); err == nil {
		t.Fatal("migrateEncryption succeeded despite an invalid stored_filename row, want error (failed migration count)")
	}
}
