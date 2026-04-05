// Package config defines the global configuration structure for Scryve and
// provides sensible defaults that can be overridden via config file, environment
// variables, or CLI flags (in increasing order of precedence).
package config

// Config holds all runtime settings for the Scryve scanner.
// Fields are exported so they can be populated by cobra flag bindings,
// the Viper loader, and direct struct assignment in tests.
type Config struct {
	// Verbose enables debug-level output from Scryve and the underlying tools.
	Verbose bool `mapstructure:"verbose" yaml:"verbose"`

	// OutputDir is the directory where reports and intermediate artifacts are written.
	// Defaults to the current working directory.
	OutputDir string `mapstructure:"output_dir" yaml:"output_dir"`

	// RateLimit is the maximum number of HTTP requests per second sent across
	// all tools in the pipeline. Defaults to 150.
	RateLimit int `mapstructure:"rate_limit" yaml:"rate_limit"`

	// ToolPaths maps tool names to their absolute binary paths.
	// When a tool is not in the map, Scryve looks for it on $PATH.
	// Example: {"subfinder": "/opt/tools/subfinder", "nuclei": "/opt/tools/nuclei"}
	ToolPaths map[string]string `mapstructure:"tool_paths" yaml:"tool_paths"`

	// Timeout is the maximum wall-clock time (in seconds) for the full scan pipeline.
	// A value of 0 means no timeout. Defaults to 3600 (1 hour).
	Timeout int `mapstructure:"timeout" yaml:"timeout"`

	// WorkDir is a temporary directory used for intermediate tool outputs during
	// a scan. When empty, a system temp directory is created automatically.
	WorkDir string `mapstructure:"work_dir" yaml:"work_dir"`
}

// DefaultConfig returns a Config populated with safe, sane defaults.
// Callers should start here and overlay values from files, env, and flags.
func DefaultConfig() Config {
	return Config{
		Verbose:   false,
		OutputDir: ".",
		RateLimit: 150,
		ToolPaths: make(map[string]string),
		Timeout:   3600,
		WorkDir:   "",
	}
}
