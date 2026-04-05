package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// These variables are set at build time via -ldflags.
//
//	Example: go build -ldflags "-X github.com/scryve/scryve/cmd.Version=1.0.0 \
//	  -X github.com/scryve/scryve/cmd.Commit=abc1234 \
//	  -X github.com/scryve/scryve/cmd.Date=2026-03-29"
var (
	// Version is the semantic version of this build (e.g. "1.0.0").
	Version = "dev"

	// Commit is the short git commit SHA of this build.
	Commit = "none"

	// Date is the ISO-8601 build date injected by the Makefile or goreleaser.
	Date = "unknown"
)

// versionCmd implements `scryve version`.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version, commit, and build date",
	Long:  `Print the Scryve binary version, git commit SHA, and build date.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("scryve version %s\n", Version)
		fmt.Printf("  commit : %s\n", Commit)
		fmt.Printf("  built  : %s\n", Date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
