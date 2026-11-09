package config

import (
	"strings"
	"testing"
)

func TestConfig_MaxFilesPerBundle(t *testing.T) {
	clearEnvVars(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.GetMaxFilesPerBundle(); got != 10 {
		t.Fatalf("default MaxFilesPerBundle = %d, want 10", got)
	}

	t.Setenv("MAX_FILES_PER_BUNDLE", "25")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load(25): %v", err)
	}
	if got := cfg.GetMaxFilesPerBundle(); got != 25 {
		t.Fatalf("MaxFilesPerBundle = %d, want 25", got)
	}

	for _, bad := range []string{"0", "-1", "101"} {
		t.Setenv("MAX_FILES_PER_BUNDLE", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MAX_FILES_PER_BUNDLE") {
			t.Errorf("MAX_FILES_PER_BUNDLE=%s: err = %v, want a MAX_FILES_PER_BUNDLE error", bad, err)
		}
	}
}
