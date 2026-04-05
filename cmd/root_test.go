package cmd_test

import (
	"strings"
	"testing"

	"github.com/scryve/scryve/cmd"
)

func TestVersionVariablesDefault(t *testing.T) {
	// Version variables should default to non-empty sentinel values.
	if cmd.Version == "" {
		t.Error("Version must not be empty string")
	}
	if cmd.Commit == "" {
		t.Error("Commit must not be empty string")
	}
	if cmd.Date == "" {
		t.Error("Date must not be empty string")
	}
}

func TestVersionDefaultValues(t *testing.T) {
	tests := []struct {
		name     string
		got      string
		contains string
	}{
		{"Version default", cmd.Version, "dev"},
		{"Commit default", cmd.Commit, "none"},
		{"Date default", cmd.Date, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got == "" {
				t.Errorf("%s: got empty string, want non-empty", tc.name)
			}
			if !strings.Contains(tc.got, tc.contains) {
				t.Errorf("%s: got %q, want it to contain %q", tc.name, tc.got, tc.contains)
			}
		})
	}
}

// TestRootCmdHasPersistentFlags verifies the global flags are registered.
func TestRootCmdHasPersistentFlags(t *testing.T) {
	root := cmd.RootCmd()
	flags := []string{"verbose", "output-dir", "rate-limit"}
	for _, name := range flags {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("expected persistent flag --%s to be registered", name)
		}
	}
}
