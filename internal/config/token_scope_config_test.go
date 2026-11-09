package config

import "testing"

func TestConfig_EnforceAPITokenScopes(t *testing.T) {
	clearEnvVars(t)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.EnforceAPITokenScopes {
		t.Fatal("API token scopes not enforced by default")
	}
	t.Setenv("ENFORCE_API_TOKEN_SCOPES", "false")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EnforceAPITokenScopes {
		t.Fatal("ENFORCE_API_TOKEN_SCOPES=false ignored")
	}
}
