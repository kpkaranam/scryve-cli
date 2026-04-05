package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Loader reads Scryve configuration in the following order of precedence
// (lowest → highest):
//
//  1. Built-in defaults (see DefaultConfig)
//  2. Config file: ~/.scryve.yaml  (or path in SCRYVE_CONFIG env var)
//  3. Environment variables prefixed with SCRYVE_
//  4. CLI flags (applied by the caller after Load returns)
type Loader struct {
	v *viper.Viper
}

// NewLoader creates a Loader with a pre-configured Viper instance.
func NewLoader() *Loader {
	v := viper.New()

	// ------------------------------------------------------------------ //
	// Defaults
	// ------------------------------------------------------------------ //
	defaults := DefaultConfig()
	v.SetDefault("verbose", defaults.Verbose)
	v.SetDefault("output_dir", defaults.OutputDir)
	v.SetDefault("rate_limit", defaults.RateLimit)
	v.SetDefault("tool_paths", defaults.ToolPaths)
	v.SetDefault("timeout", defaults.Timeout)
	v.SetDefault("work_dir", defaults.WorkDir)

	// ------------------------------------------------------------------ //
	// Config file search path
	// ------------------------------------------------------------------ //
	if cfgFile := os.Getenv("SCRYVE_CONFIG"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(home)
		}
		v.AddConfigPath(".")
		v.SetConfigName(".scryve")
		v.SetConfigType("yaml")
	}

	// ------------------------------------------------------------------ //
	// Environment variables
	// ------------------------------------------------------------------ //
	// All env vars are prefixed SCRYVE_ and use underscores.
	// E.g.: SCRYVE_RATE_LIMIT=300  →  cfg.RateLimit = 300
	v.SetEnvPrefix("SCRYVE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	return &Loader{v: v}
}

// Load reads the config file (if present), applies environment variables,
// and returns a fully populated Config struct.
//
// A missing config file is not treated as an error — callers rely only on
// defaults and environment variables in that case.
func (l *Loader) Load() (Config, error) {
	if err := l.v.ReadInConfig(); err != nil {
		// It is valid for the config file not to exist.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return Config{}, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := l.v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshaling config: %w", err)
	}

	// Expand any ~ in paths.
	cfg.OutputDir = expandHome(cfg.OutputDir)
	cfg.WorkDir = expandHome(cfg.WorkDir)

	if cfg.ToolPaths == nil {
		cfg.ToolPaths = make(map[string]string)
	}
	for k, v := range cfg.ToolPaths {
		cfg.ToolPaths[k] = expandHome(v)
	}

	return cfg, nil
}

// ConfigFilePath returns the path of the config file that was actually used,
// or an empty string if no file was loaded.
func (l *Loader) ConfigFilePath() string {
	return l.v.ConfigFileUsed()
}

// expandHome replaces a leading ~ with the current user's home directory.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}
