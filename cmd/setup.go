// Package cmd — setup subcommand.
// scryve setup        — installs all missing required tools into ~/.scryve/bin/
// scryve setup --check — reports tool status without installing anything
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scryve/scryve/pkg/toolmanager"
)

// setupFlags holds flags specific to the setup subcommand.
type setupFlags struct {
	checkOnly bool
}

var setupOpts setupFlags

// setupCmd implements `scryve setup`.
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Check and install required security tools (subfinder, httpx, naabu, nuclei)",
	Long: `Setup verifies that all tools Scryve depends on are installed.

When run without flags, any missing tools are downloaded from GitHub Releases
and placed in ~/.scryve/bin/. That directory is automatically added to PATH
for subsequent scryve commands.

Use --check to report tool status without making any changes.

Examples:
  scryve setup               # install missing tools
  scryve setup --check       # check only, do not install`,

	RunE: func(cmd *cobra.Command, args []string) error {
		mgr := toolmanager.NewManager()
		mgr.Verbose = cfg.Verbose

		fmt.Fprintln(os.Stdout, "Checking tools...")

		installed, missing, err := mgr.CheckAll()
		if err != nil {
			return fmt.Errorf("setup: could not check tools: %w", err)
		}

		// Report each tool's status.
		for _, tool := range installed {
			fmt.Fprintf(os.Stdout, "  %-12s ok (%s)\n", tool.Name+":", mgr.BinPath(tool.Name))
		}
		for _, tool := range missing {
			fmt.Fprintf(os.Stdout, "  %-12s not found\n", tool.Name+":")
		}

		if len(missing) == 0 {
			fmt.Fprintln(os.Stdout, "\nAll tools are installed. Run 'scryve scan <domain>' to start.")
			return nil
		}

		if setupOpts.checkOnly {
			names := toolNames(missing)
			fmt.Fprintf(os.Stdout, "\nMissing tools: %s\n", strings.Join(names, ", "))
			fmt.Fprintln(os.Stdout, "Run 'scryve setup' to install them automatically.")
			return nil
		}

		// Install missing tools.
		fmt.Fprintf(os.Stdout, "\nInstalling %d tool(s) to %s...\n", len(missing), mgr.BinDir)

		for _, tool := range missing {
			if err := mgr.InstallTool(tool, os.Stdout); err != nil {
				return fmt.Errorf("setup: failed to install %q: %w", tool.Name, err)
			}
		}

		// Add managed bin directory to PATH for this process session.
		if err := mgr.EnsurePath(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not update PATH: %v\n", err)
		}

		fmt.Fprintln(os.Stdout, "\nAll tools installed! Run 'scryve scan <domain>' to start.")
		return nil
	},
}

// toolNames extracts the Name field from a slice of Tools.
func toolNames(tools []toolmanager.Tool) []string {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	return names
}

func init() {
	rootCmd.AddCommand(setupCmd)

	setupCmd.Flags().BoolVar(
		&setupOpts.checkOnly, "check", false,
		"check tool availability only; do not install anything",
	)
}
