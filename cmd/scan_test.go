package cmd_test

import (
	"testing"

	"github.com/scryve/scryve/cmd"
)

// TestScanCommandRegistered verifies the scan command is wired into the root.
func TestScanCommandRegistered(t *testing.T) {
	found := false
	for _, sub := range cmd.RootCmd().Commands() {
		if sub.Use == "scan <domain>" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'scan' subcommand to be registered on rootCmd")
	}
}

// TestVersionCommandRegistered verifies the version command is wired into root.
func TestVersionCommandRegistered(t *testing.T) {
	found := false
	for _, sub := range cmd.RootCmd().Commands() {
		if sub.Use == "version" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'version' subcommand to be registered on rootCmd")
	}
}

// TestScanRequiresDomain verifies scan returns an error when no domain is given.
func TestScanRequiresDomain(t *testing.T) {
	root := cmd.RootCmd()
	root.SetArgs([]string{"scan"})
	if err := root.Execute(); err == nil {
		t.Error("expected an error when scan is run without a domain argument")
	}
	// Reset args so subsequent tests are not affected.
	root.SetArgs([]string{})
}
