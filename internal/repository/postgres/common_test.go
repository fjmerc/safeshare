package postgres

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidateStoredFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			name:     "valid simple filename",
			filename: "test.txt",
			wantErr:  false,
		},
		{
			name:     "valid filename with underscore",
			filename: "test_file.txt",
			wantErr:  false,
		},
		{
			name:     "valid filename with dash",
			filename: "test-file.txt",
			wantErr:  false,
		},
		{
			name:     "valid UUID filename",
			filename: "a1b2c3d4-e5f6-7890-abcd-ef1234567890.dat",
			wantErr:  false,
		},
		{
			name:     "empty filename",
			filename: "",
			wantErr:  true,
		},
		{
			name:     "filename with forward slash",
			filename: "path/to/file.txt",
			wantErr:  true,
		},
		{
			name:     "filename with backslash",
			filename: "path\\to\\file.txt",
			wantErr:  true,
		},
		{
			name:     "filename with path traversal",
			filename: "../../../etc/passwd",
			wantErr:  true,
		},
		{
			name:     "hidden file (starts with dot)",
			filename: ".hidden",
			wantErr:  true,
		},
		{
			name:     "filename with special characters",
			filename: "file@name.txt",
			wantErr:  true,
		},
		{
			name:     "filename with space",
			filename: "file name.txt",
			wantErr:  true,
		},
		{
			name:     "filename with unicode",
			filename: "файл.txt",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateStoredFilename(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateStoredFilename(%q) error = %v, wantErr %v", tt.filename, err, tt.wantErr)
			}
		})
	}
}

func TestEscapeLikePattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no special characters",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "percent sign",
			input:    "hello%world",
			expected: "hello\\%world",
		},
		{
			name:     "underscore",
			input:    "hello_world",
			expected: "hello\\_world",
		},
		{
			name:     "backslash",
			input:    "hello\\world",
			expected: "hello\\\\world",
		},
		{
			name:     "multiple special characters",
			input:    "100% match_test\\path",
			expected: "100\\% match\\_test\\\\path",
		},
		{
			name:     "null byte removed",
			input:    "hello\x00world",
			expected: "helloworld",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeLikePattern(tt.input)
			if result != tt.expected {
				t.Errorf("escapeLikePattern(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGenerateClaimCode(t *testing.T) {
	code1, err := generateClaimCode()
	if err != nil {
		t.Fatalf("generateClaimCode() error = %v", err)
	}

	// Check length (8 characters)
	if len(code1) != 8 {
		t.Errorf("generateClaimCode() length = %d, want 8", len(code1))
	}

	// Check that it only contains URL-safe base64 characters
	for _, c := range code1 {
		isValid := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' ||
			c == '_'
		if !isValid {
			t.Errorf("generateClaimCode() contains invalid character: %c", c)
		}
	}

	// Generate another code and verify uniqueness
	code2, err := generateClaimCode()
	if err != nil {
		t.Fatalf("generateClaimCode() error = %v", err)
	}

	if code1 == code2 {
		t.Error("generateClaimCode() should generate unique codes")
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "serialization failure",
			err:      &pgconn.PgError{Code: SerializationFailure},
			expected: true,
		},
		{
			name:     "deadlock detected",
			err:      &pgconn.PgError{Code: DeadlockDetected},
			expected: true,
		},
		{
			name:     "unique violation (not retryable)",
			err:      &pgconn.PgError{Code: UniqueViolation},
			expected: false,
		},
		{
			name:     "foreign key violation (not retryable)",
			err:      &pgconn.PgError{Code: ForeignKeyViolation},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetryableError(tt.err)
			if result != tt.expected {
				t.Errorf("isRetryableError() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsUniqueViolation(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "unique violation",
			err:      &pgconn.PgError{Code: UniqueViolation},
			expected: true,
		},
		{
			name:     "foreign key violation",
			err:      &pgconn.PgError{Code: ForeignKeyViolation},
			expected: false,
		},
		{
			name:     "deadlock detected",
			err:      &pgconn.PgError{Code: DeadlockDetected},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isUniqueViolation(tt.err)
			if result != tt.expected {
				t.Errorf("isUniqueViolation() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTxOptions(t *testing.T) {
	opts := TxOptions()

	// Just verify it returns valid options
	if opts.IsoLevel == "" {
		t.Error("TxOptions() should set isolation level")
	}
}

func TestScanNullableString(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.NullString
		expected string
	}{
		{
			name:     "valid string",
			input:    sql.NullString{String: "hello", Valid: true},
			expected: "hello",
		},
		{
			name:     "null string",
			input:    sql.NullString{String: "", Valid: false},
			expected: "",
		},
		{
			name:     "valid empty string",
			input:    sql.NullString{String: "", Valid: true},
			expected: "",
		},
		{
			name:     "invalid with value",
			input:    sql.NullString{String: "hello", Valid: false},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanNullableString(tt.input)
			if result != tt.expected {
				t.Errorf("scanNullableString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestScanNullableInt64(t *testing.T) {
	tests := []struct {
		name        string
		input       sql.NullInt64
		expectNil   bool
		expectedVal int64
	}{
		{
			name:        "valid int64",
			input:       sql.NullInt64{Int64: 42, Valid: true},
			expectNil:   false,
			expectedVal: 42,
		},
		{
			name:      "null int64",
			input:     sql.NullInt64{Int64: 0, Valid: false},
			expectNil: true,
		},
		{
			name:        "valid zero",
			input:       sql.NullInt64{Int64: 0, Valid: true},
			expectNil:   false,
			expectedVal: 0,
		},
		{
			name:      "invalid with value",
			input:     sql.NullInt64{Int64: 100, Valid: false},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanNullableInt64(tt.input)
			if tt.expectNil {
				if result != nil {
					t.Errorf("scanNullableInt64() = %v, want nil", *result)
				}
			} else {
				if result == nil {
					t.Error("scanNullableInt64() = nil, want non-nil")
				} else if *result != tt.expectedVal {
					t.Errorf("scanNullableInt64() = %d, want %d", *result, tt.expectedVal)
				}
			}
		})
	}
}

func TestScanNullableInt(t *testing.T) {
	tests := []struct {
		name        string
		input       sql.NullInt64
		expectNil   bool
		expectedVal int
	}{
		{
			name:        "valid int",
			input:       sql.NullInt64{Int64: 42, Valid: true},
			expectNil:   false,
			expectedVal: 42,
		},
		{
			name:      "null int",
			input:     sql.NullInt64{Int64: 0, Valid: false},
			expectNil: true,
		},
		{
			name:        "valid zero",
			input:       sql.NullInt64{Int64: 0, Valid: true},
			expectNil:   false,
			expectedVal: 0,
		},
		{
			name:      "invalid with value",
			input:     sql.NullInt64{Int64: 100, Valid: false},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanNullableInt(tt.input)
			if tt.expectNil {
				if result != nil {
					t.Errorf("scanNullableInt() = %v, want nil", *result)
				}
			} else {
				if result == nil {
					t.Error("scanNullableInt() = nil, want non-nil")
				} else if *result != tt.expectedVal {
					t.Errorf("scanNullableInt() = %d, want %d", *result, tt.expectedVal)
				}
			}
		})
	}
}

func TestScanNullableTime(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name        string
		input       sql.NullTime
		expectNil   bool
		expectedVal time.Time
	}{
		{
			name:        "valid time",
			input:       sql.NullTime{Time: now, Valid: true},
			expectNil:   false,
			expectedVal: now,
		},
		{
			name:      "null time",
			input:     sql.NullTime{Time: time.Time{}, Valid: false},
			expectNil: true,
		},
		{
			name:        "valid zero time",
			input:       sql.NullTime{Time: time.Time{}, Valid: true},
			expectNil:   false,
			expectedVal: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanNullableTime(tt.input)
			if tt.expectNil {
				if result != nil {
					t.Error("scanNullableTime() should return nil")
				}
			} else {
				if result == nil {
					t.Error("scanNullableTime() = nil, want non-nil")
				} else if !result.Equal(tt.expectedVal) {
					t.Errorf("scanNullableTime() = %v, want %v", *result, tt.expectedVal)
				}
			}
		})
	}
}

func TestBoolToInt(t *testing.T) {
	tests := []struct {
		name     string
		input    bool
		expected int
	}{
		{
			name:     "true",
			input:    true,
			expected: 1,
		},
		{
			name:     "false",
			input:    false,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := boolToInt(tt.input)
			if result != tt.expected {
				t.Errorf("boolToInt(%v) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseBlockedExtensions(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "single extension",
			input:    ".exe",
			expected: []string{".exe"},
		},
		{
			name:     "multiple extensions",
			input:    ".exe,.bat,.cmd",
			expected: []string{".exe", ".bat", ".cmd"},
		},
		{
			name:     "with spaces",
			input:    ".exe, .bat, .cmd",
			expected: []string{".exe", ".bat", ".cmd"},
		},
		{
			name:     "with empty parts",
			input:    ".exe,,,.bat",
			expected: []string{".exe", ".bat"},
		},
		{
			name:     "only commas",
			input:    ",,,",
			expected: []string{},
		},
		{
			name:     "spaces only",
			input:    "   ",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBlockedExtensions(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parseBlockedExtensions(%q) len = %d, want %d", tt.input, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("parseBlockedExtensions(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestPostgreSQLErrorCodeConstants(t *testing.T) {
	// Verify constants have expected values
	if UniqueViolation != "23505" {
		t.Errorf("UniqueViolation = %q, want 23505", UniqueViolation)
	}
	if ForeignKeyViolation != "23503" {
		t.Errorf("ForeignKeyViolation = %q, want 23503", ForeignKeyViolation)
	}
	if SerializationFailure != "40001" {
		t.Errorf("SerializationFailure = %q, want 40001", SerializationFailure)
	}
	if DeadlockDetected != "40P01" {
		t.Errorf("DeadlockDetected = %q, want 40P01", DeadlockDetected)
	}
}
