// Package cmd contains all CLI commands for the Scryve security scanner.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/scryve/scryve/pkg/config"
)

var (
	// cfg holds the global configuration resolved from file, env, and flags.
	cfg config.Config

	// rootCmd is the base command — running scryve without subcommands prints help.
	rootCmd = &cobra.Command{
		Use:   "scryve",
		Short: "Scryve — unified security scanner",
		Long: `Scryve is a domain-in, compliance-report-out security scanner.

It chains subfinder → httpx → naabu → nuclei into a single command and
maps findings to compliance frameworks (PCI DSS 4.0, ISO 27001, OWASP Top 10).

Example:
  scryve scan example.com
  scryve scan example.com --compliance pci-dss-4.0 --output report.html`,
	}
)

// RootCmd returns the cobra root command.
// Exposed for testing — callers should use Execute() in production code.
func RootCmd() *cobra.Command {
	return rootCmd
}

// CfgRateLimit returns the current rate-limit value from the global config.
// It reflects whatever the --rate-limit flag was set to (or its default).
// Exported for tests that need to inspect how CLI flags map to cfg values.
func CfgRateLimit() int {
	return cfg.RateLimit
}

// Execute is the entry point called by main.go.
// It runs the root command and exits with code 1 on error.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Persistent flags are available to all subcommands.
	rootCmd.PersistentFlags().BoolVarP(
		&cfg.Verbose, "verbose", "v", false,
		"enable verbose output (includes debug logs from each tool)",
	)
	rootCmd.PersistentFlags().StringVar(
		&cfg.OutputDir, "output-dir", ".",
		"directory where reports and intermediate artifacts are written",
	)
	rootCmd.PersistentFlags().IntVar(
		&cfg.RateLimit, "rate-limit", 150,
		"maximum HTTP requests per second across all tools",
	)
}

// initConfig loads configuration from ~/.scryve.yaml and environment variables,
// then overlays any CLI flag values.
func initConfig() {
	loader := config.NewLoader()
	loaded, err := loader.Load()
	if err != nil {
		// Config file is optional — only warn, do not fail.
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "warning: could not load config file: %v\n", err)
		}
		return
	}

	// CLI flags take precedence — only apply loaded values where the flag was
	// not explicitly set by the user.
	if !rootCmd.PersistentFlags().Changed("verbose") {
		cfg.Verbose = loaded.Verbose
	}
	if !rootCmd.PersistentFlags().Changed("output-dir") {
		cfg.OutputDir = loaded.OutputDir
	}
	if !rootCmd.PersistentFlags().Changed("rate-limit") {
		cfg.RateLimit = loaded.RateLimit
	}

	// Always propagate tool paths from config (not settable as flags).
	cfg.ToolPaths = loaded.ToolPaths
}
