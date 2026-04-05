// Package main is the entry point for the Scryve CLI.
// Scryve is a domain-in, compliance-report-out security scanner that orchestrates
// subfinder, httpx, naabu, and nuclei into a single unified pipeline.
package main

import "github.com/scryve/scryve/cmd"

func main() {
	cmd.Execute()
}
