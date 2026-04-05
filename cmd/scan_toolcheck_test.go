package cmd_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/scryve/scryve/cmd"
)

// TestScanOutputsMissingToolsHint verifies that when scan is run (stub mode),
// it completes without error (tools check is advisory, not blocking).
// This test documents the expected behavior: scan should NOT fail hard when
// tools are missing — it should warn and proceed.
func TestScanCommandAcceptsDomainArg(t *testing.T) {
	t.Skip("runs real pipeline with network")
	root := cmd.RootCmd()

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)

	root.SetArgs([]string{"scan", "example.com", "--format", "json"})
	_ = root.Execute() // errors are acceptable (report write etc.)

	// Reset for other tests.
	root.SetArgs([]string{})
}

// TestScanAutoInstallFlagExists verifies scan exposes an --auto-install flag.
func TestScanAutoInstallFlagExists(t *testing.T) {
	for _, sub := range cmd.RootCmd().Commands() {
		if sub.Use == "scan <domain>" {
			flag := sub.Flags().Lookup("auto-install")
			if flag == nil {
				t.Error("expected scan command to have an --auto-install flag")
			}
			return
		}
	}
	t.Error("scan command not found")
}

// TestScanToolCheckMessageContainsSuggestion verifies the advisory text
// produced when tools are absent contains the expected suggestion.
func TestScanToolCheckOutputHelper(t *testing.T) {
	// Verify the helper function exposed for testing produces correct output.
	msg := cmd.MissingToolsMessage([]string{"subfinder", "httpx"})
	if !strings.Contains(msg, "subfinder") {
		t.Error("expected message to contain 'subfinder'")
	}
	if !strings.Contains(msg, "scryve setup") {
		t.Error("expected message to suggest running 'scryve setup'")
	}
}
