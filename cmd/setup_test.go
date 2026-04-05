package cmd_test

import (
	"testing"

	"github.com/scryve/scryve/cmd"
)

// TestSetupCommandRegistered verifies the setup command is wired into the root.
func TestSetupCommandRegistered(t *testing.T) {
	found := false
	for _, sub := range cmd.RootCmd().Commands() {
		if sub.Use == "setup" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'setup' subcommand to be registered on rootCmd")
	}
}

// TestSetupCommandHasCheckFlag verifies the setup command exposes a --check flag.
func TestSetupCommandHasCheckFlag(t *testing.T) {
	var setupCmd interface {
		Flags() interface{ Lookup(string) interface{} }
	}
	_ = setupCmd

	for _, sub := range cmd.RootCmd().Commands() {
		if sub.Use == "setup" {
			flag := sub.Flags().Lookup("check")
			if flag == nil {
				t.Error("expected setup command to have a --check flag")
			}
			return
		}
	}
	t.Error("setup command not found")
}

// TestSetupCommandHasShortDescription verifies the setup command has a
// non-empty short description.
func TestSetupCommandHasShortDescription(t *testing.T) {
	for _, sub := range cmd.RootCmd().Commands() {
		if sub.Use == "setup" {
			if sub.Short == "" {
				t.Error("expected setup command to have a Short description")
			}
			return
		}
	}
	t.Error("setup command not found")
}
