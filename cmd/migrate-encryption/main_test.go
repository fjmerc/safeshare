package main

import (
	"os"
	"path/filepath"
	"testing"

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
		name           string
		data           []byte
		encrypted      bool
		useLegacy      bool
		expectedMigrate bool
	}{
		{
			name:           "legacy_encrypted_file",
			data:           []byte("This is a test file for legacy encryption"),
			encrypted:      true,
			useLegacy:      true,
			expectedMigrate: true,
		},
		{
			name:           "sfse1_encrypted_file",
			data:           []byte("This is a test file for SFSE1 encryption"),
			encrypted:      true,
			useLegacy:      false,
			expectedMigrate: false,
		},
		{
			name:           "unencrypted_file",
			data:           []byte("This is an unencrypted test file"),
			encrypted:      false,
			useLegacy:      false,
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

			// Check if file is SFSE1
			isStreamEnc, err := utils.IsStreamEncrypted(filePath)
			if err != nil {
				t.Fatalf("Failed to check encryption format: %v", err)
			}

			if tt.expectedMigrate {
				// Should be SFSE1 now
				if !isStreamEnc {
					t.Errorf("Expected file to be SFSE1 encrypted after migration, but it's not")
				}

				// Verify can decrypt
				decrypted := make([]byte, 0)
				tempDecPath := filePath + ".dec"
				if err := utils.DecryptFileStreaming(filePath, tempDecPath, testKey); err != nil {
					t.Fatalf("Failed to decrypt migrated file: %v", err)
				}
				decrypted, err = os.ReadFile(tempDecPath)
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
					// Should still be SFSE1
					if !isStreamEnc {
						t.Errorf("SFSE1 file should remain SFSE1")
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
