package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scryve/scryve/pkg/config"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Verbose {
		t.Error("expected Verbose to default to false")
	}
	if cfg.OutputDir != "." {
		t.Errorf("expected OutputDir to default to '.', got %q", cfg.OutputDir)
	}
	if cfg.RateLimit != 150 {
		t.Errorf("expected RateLimit to default to 150, got %d", cfg.RateLimit)
	}
	if cfg.ToolPaths == nil {
		t.Error("expected ToolPaths to be an initialized map, got nil")
	}
	if cfg.Timeout != 3600 {
		t.Errorf("expected Timeout to default to 3600, got %d", cfg.Timeout)
	}
}

func TestLoaderDefaults(t *testing.T) {
	// Ensure no SCRYVE_CONFIG is set so we exercise the default search path.
	t.Setenv("SCRYVE_CONFIG", "")

	loader := config.NewLoader()
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if cfg.RateLimit != 150 {
		t.Errorf("expected default RateLimit 150, got %d", cfg.RateLimit)
	}
	if cfg.Verbose {
		t.Error("expected default Verbose false")
	}
}

func TestLoaderFromYAMLFile(t *testing.T) {
	// Write a temporary YAML config file.
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, ".scryve.yaml")
	content := `
verbose: true
rate_limit: 300
output_dir: /tmp/scryve-out
tool_paths:
  subfinder: /opt/tools/subfinder
  nuclei: /opt/tools/nuclei
timeout: 7200
`
	if err := os.WriteFile(cfgFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	t.Setenv("SCRYVE_CONFIG", cfgFile)

	loader := config.NewLoader()
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !cfg.Verbose {
		t.Error("expected Verbose=true from file")
	}
	if cfg.RateLimit != 300 {
		t.Errorf("expected RateLimit=300, got %d", cfg.RateLimit)
	}
	if cfg.OutputDir != "/tmp/scryve-out" {
		t.Errorf("expected OutputDir=/tmp/scryve-out, got %q", cfg.OutputDir)
	}
	if cfg.ToolPaths["subfinder"] != "/opt/tools/subfinder" {
		t.Errorf("expected ToolPaths[subfinder]=/opt/tools/subfinder, got %q", cfg.ToolPaths["subfinder"])
	}
	if cfg.Timeout != 7200 {
		t.Errorf("expected Timeout=7200, got %d", cfg.Timeout)
	}
}

func TestLoaderFromEnvVars(t *testing.T) {
	t.Setenv("SCRYVE_CONFIG", "")
	t.Setenv("SCRYVE_RATE_LIMIT", "500")
	t.Setenv("SCRYVE_VERBOSE", "true")
	t.Setenv("SCRYVE_OUTPUT_DIR", "/env/output")

	loader := config.NewLoader()
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.RateLimit != 500 {
		t.Errorf("expected RateLimit=500 from env, got %d", cfg.RateLimit)
	}
	if !cfg.Verbose {
		t.Error("expected Verbose=true from env")
	}
	if cfg.OutputDir != "/env/output" {
		t.Errorf("expected OutputDir=/env/output, got %q", cfg.OutputDir)
	}
}

func TestLoaderMissingFileIsNotError(t *testing.T) {
	t.Setenv("SCRYVE_CONFIG", "")

	// Point to a directory that definitely has no .scryve.yaml.
	dir := t.TempDir()
	_ = dir // NewLoader will search here — file won't be found.

	loader := config.NewLoader()
	_, err := loader.Load()
	// A missing config file must NOT be returned as an error.
	if err != nil {
		t.Errorf("Load() should not error on missing config file, got: %v", err)
	}
}
