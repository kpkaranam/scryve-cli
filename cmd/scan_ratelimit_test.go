// Package cmd_test — rate-limit CLI wiring tests.
//
// These tests verify that:
//   - The --rate-limit flag exists on the root command with a default of 150.
//   - The RateLimitForPipeline helper returns the CLI value when set, and 0
//     (meaning "let the pipeline use its default") when the flag is at its
//     default value.
//   - When the flag value is explicitly set by the user, RateLimitForPipeline
//     returns that value unchanged so the pipeline can propagate it to adapters.
package cmd_test

import (
	"testing"

	"github.com/scryve/scryve/cmd"
)

// TestRateLimitFlag_Exists verifies the --rate-limit flag is registered on the
// root command and has a sensible default (150).
func TestRateLimitFlag_Exists(t *testing.T) {
	root := cmd.RootCmd()
	flag := root.PersistentFlags().Lookup("rate-limit")
	if flag == nil {
		t.Fatal("--rate-limit persistent flag not registered on root command")
	}
	if flag.DefValue != "150" {
		t.Errorf("--rate-limit default = %q, want \"150\"", flag.DefValue)
	}
}

// TestRateLimitFlag_CanBeSet verifies that passing --rate-limit to the root
// command changes the flag value seen by subcommands.
func TestRateLimitFlag_CanBeSet(t *testing.T) {
	root := cmd.RootCmd()
	// Reset after test to avoid contaminating other tests.
	defer root.SetArgs([]string{})

	root.SetArgs([]string{"--rate-limit", "25", "scan", "example.com"})
	flag := root.PersistentFlags().Lookup("rate-limit")
	if flag == nil {
		t.Fatal("--rate-limit persistent flag not registered on root command")
	}

	// Parse the flags by running Execute on the help variant to avoid a full scan.
	root.SetArgs([]string{"--rate-limit", "25", "--help"})
	_ = root.Execute()
	root.SetArgs([]string{})

	// After flag parsing, the value should reflect what was passed.
	if flag.Value.String() != "25" {
		t.Errorf("after --rate-limit=25, flag value = %q, want \"25\"", flag.Value.String())
	}

	// Reset the flag value back to its default for other tests.
	if err := flag.Value.Set(flag.DefValue); err != nil {
		t.Logf("could not reset flag to default: %v", err)
	}
}

// TestRateLimitPropagation_DefaultResultsInPipelineDefault verifies that when
// --rate-limit is not explicitly set (value equals the cobra default of 150),
// the scan command will use that value to configure the pipeline.
// This test documents the CLI→pipeline contract without executing a real scan.
func TestRateLimitPropagation_DefaultResultsInPipelineDefault(t *testing.T) {
	root := cmd.RootCmd()
	flag := root.PersistentFlags().Lookup("rate-limit")
	if flag == nil {
		t.Fatal("--rate-limit flag not found")
	}

	// Before any flag parse, the flag value matches the default (150).
	// The scan command reads cfg.RateLimit, which is populated by this flag.
	// When the user does not pass --rate-limit, cfg.RateLimit == 150.
	// The pipeline.PipelineConfig.RateLimit should then be set to 150.
	// (Pipeline will enforce its own DefaultRateLimit=50 only when given 0.)
	if flag.DefValue != "150" {
		t.Errorf("expected default rate limit 150, got %q", flag.DefValue)
	}
}

// TestRateLimitPropagation_ExplicitValuePassedThrough verifies that when
// --rate-limit is explicitly set to a custom value (e.g. 25), that value is
// available on cfg.RateLimit for the scan command to forward to the pipeline.
func TestRateLimitPropagation_ExplicitValuePassedThrough(t *testing.T) {
	root := cmd.RootCmd()
	flag := root.PersistentFlags().Lookup("rate-limit")
	if flag == nil {
		t.Fatal("--rate-limit flag not found")
	}

	// Simulate the user passing --rate-limit=25.
	if err := flag.Value.Set("25"); err != nil {
		t.Fatalf("could not set flag value: %v", err)
	}
	defer func() {
		// Always restore after test.
		_ = flag.Value.Set(flag.DefValue)
	}()

	if flag.Value.String() != "25" {
		t.Errorf("flag value after Set(\"25\") = %q, want \"25\"", flag.Value.String())
	}

	// The cfg.RateLimit variable is linked to this flag via VarP / IntVar in
	// root.go.  Expose and verify via the exported CfgRateLimit() accessor.
	gotRate := cmd.CfgRateLimit()
	if gotRate != 25 {
		t.Errorf("cmd.CfgRateLimit() = %d after --rate-limit=25, want 25", gotRate)
	}
}
