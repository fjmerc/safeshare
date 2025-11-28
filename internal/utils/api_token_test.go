package utils

import (
	"strings"
	"testing"
)

func TestGenerateAPIToken(t *testing.T) {
	token, prefix, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken() error = %v", err)
	}

	// Check token format
	if !strings.HasPrefix(token, APITokenPrefix) {
		t.Errorf("token should start with %q, got %q", APITokenPrefix, token[:len(APITokenPrefix)])
	}

	// Check token length
	if len(token) != APITokenLength {
		t.Errorf("token length = %d, want %d", len(token), APITokenLength)
	}

	// Check prefix length
	if len(prefix) != APITokenPrefixDisplayLength {
		t.Errorf("prefix length = %d, want %d", len(prefix), APITokenPrefixDisplayLength)
	}

	// Check prefix matches token start
	if !strings.HasPrefix(token, prefix) {
		t.Errorf("prefix %q should match start of token %q", prefix, token[:APITokenPrefixDisplayLength])
	}

	// Generate another token and ensure they're different
	token2, _, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken() second call error = %v", err)
	}
	if token == token2 {
		t.Error("two generated tokens should be different")
	}
}

func TestHashAPIToken(t *testing.T) {
	token := "safeshare_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hash := HashAPIToken(token)

	// Hash should be 64 hex characters (SHA-256)
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Same token should produce same hash
	hash2 := HashAPIToken(token)
	if hash != hash2 {
		t.Error("same token should produce same hash")
	}

	// Different token should produce different hash
	differentToken := "safeshare_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	differentHash := HashAPIToken(differentToken)
	if hash == differentHash {
		t.Error("different tokens should produce different hashes")
	}
}

func TestValidateAPITokenFormat(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{
			name:  "valid token",
			token: "safeshare_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:  true,
		},
		{
			name:  "valid token with uppercase hex",
			token: "safeshare_0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			want:  true,
		},
		{
			name:  "wrong prefix",
			token: "wrongpfx_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:  false,
		},
		{
			name:  "too short",
			token: "safeshare_0123456789abcdef",
			want:  false,
		},
		{
			name:  "too long",
			token: "safeshare_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
			want:  false,
		},
		{
			name:  "invalid hex characters",
			token: "safeshare_ghijklmnopqrstuv0123456789abcdef0123456789abcdef0123456789abcdef",
			want:  false,
		},
		{
			name:  "empty string",
			token: "",
			want:  false,
		},
		{
			name:  "just prefix",
			token: "safeshare_",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateAPITokenFormat(tt.token)
			if got != tt.want {
				t.Errorf("ValidateAPITokenFormat(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name        string
		scopes      []string
		wantInvalid []string
		wantErr     bool
	}{
		{
			name:        "all valid scopes",
			scopes:      []string{"upload", "download", "manage", "admin"},
			wantInvalid: nil,
			wantErr:     false,
		},
		{
			name:        "single valid scope",
			scopes:      []string{"upload"},
			wantInvalid: nil,
			wantErr:     false,
		},
		{
			name:        "one invalid scope",
			scopes:      []string{"upload", "invalid"},
			wantInvalid: []string{"invalid"},
			wantErr:     true,
		},
		{
			name:        "all invalid scopes",
			scopes:      []string{"foo", "bar"},
			wantInvalid: []string{"foo", "bar"},
			wantErr:     true,
		},
		{
			name:        "empty scopes",
			scopes:      []string{},
			wantInvalid: nil,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotInvalid, err := ValidateScopes(tt.scopes)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScopes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(gotInvalid) != len(tt.wantInvalid) {
				t.Errorf("ValidateScopes() invalid = %v, want %v", gotInvalid, tt.wantInvalid)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		name          string
		scopeString   string
		requiredScope string
		want          bool
	}{
		{
			name:          "has exact scope",
			scopeString:   "upload,download",
			requiredScope: "upload",
			want:          true,
		},
		{
			name:          "missing scope",
			scopeString:   "upload,download",
			requiredScope: "admin",
			want:          false,
		},
		{
			name:          "admin grants all",
			scopeString:   "admin",
			requiredScope: "upload",
			want:          true,
		},
		{
			name:          "admin grants manage",
			scopeString:   "admin",
			requiredScope: "manage",
			want:          true,
		},
		{
			name:          "single scope match",
			scopeString:   "upload",
			requiredScope: "upload",
			want:          true,
		},
		{
			name:          "empty scope string",
			scopeString:   "",
			requiredScope: "upload",
			want:          false,
		},
		{
			name:          "scope with spaces",
			scopeString:   "upload , download , manage",
			requiredScope: "download",
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasScope(tt.scopeString, tt.requiredScope)
			if got != tt.want {
				t.Errorf("HasScope(%q, %q) = %v, want %v", tt.scopeString, tt.requiredScope, got, tt.want)
			}
		})
	}
}

func TestNormalizeScopes(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{
			name:   "removes duplicates",
			scopes: []string{"upload", "upload", "download"},
			want:   []string{"upload", "download"},
		},
		{
			name:   "trims whitespace",
			scopes: []string{" upload ", "  download  "},
			want:   []string{"upload", "download"},
		},
		{
			name:   "removes empty strings",
			scopes: []string{"upload", "", "download", "  "},
			want:   []string{"upload", "download"},
		},
		{
			name:   "empty input",
			scopes: []string{},
			want:   nil,
		},
		{
			name:   "all empty strings",
			scopes: []string{"", "  ", ""},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeScopes(tt.scopes)
			if len(got) != len(tt.want) {
				t.Errorf("NormalizeScopes() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("NormalizeScopes()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestScopesToString(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   string
	}{
		{
			name:   "multiple scopes",
			scopes: []string{"upload", "download", "manage"},
			want:   "upload,download,manage",
		},
		{
			name:   "single scope",
			scopes: []string{"upload"},
			want:   "upload",
		},
		{
			name:   "empty scopes",
			scopes: []string{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScopesToString(tt.scopes)
			if got != tt.want {
				t.Errorf("ScopesToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStringToScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopeStr string
		want     []string
	}{
		{
			name:     "multiple scopes",
			scopeStr: "upload,download,manage",
			want:     []string{"upload", "download", "manage"},
		},
		{
			name:     "single scope",
			scopeStr: "upload",
			want:     []string{"upload"},
		},
		{
			name:     "empty string",
			scopeStr: "",
			want:     []string{},
		},
		{
			name:     "scopes with spaces",
			scopeStr: " upload , download , manage ",
			want:     []string{"upload", "download", "manage"},
		},
		{
			name:     "filters empty after split",
			scopeStr: "upload,,download",
			want:     []string{"upload", "download"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringToScopes(tt.scopeStr)
			if len(got) != len(tt.want) {
				t.Errorf("StringToScopes(%q) = %v, want %v", tt.scopeStr, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("StringToScopes(%q)[%d] = %q, want %q", tt.scopeStr, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestMaskAPIToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "valid token",
			token: "safeshare_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:  "safeshare_01***def",
		},
		{
			name:  "empty string",
			token: "",
			want:  "",
		},
		{
			name:  "short token uses generic masking",
			token: "short",
			want:  "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskAPIToken(tt.token)
			if got != tt.want {
				t.Errorf("MaskAPIToken(%q) = %q, want %q", tt.token, got, tt.want)
			}
		})
	}
}
