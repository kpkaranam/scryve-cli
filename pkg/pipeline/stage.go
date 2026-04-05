// Package pipeline provides the sequential stage orchestrator for Scryve.
// It iterates through a list of Stage definitions, runs the corresponding
// adapter for each stage, and feeds accumulated data (subdomains, live hosts,
// open ports) forward into subsequent stages.
package pipeline

import "github.com/scryve/scryve/pkg/adapter"

// Stage defines a single step in the pipeline, binding a human-readable name
// to a registered adapter and specifying whether failure is fatal.
type Stage struct {
	// Name is the human-readable label shown in progress output and reports.
	Name string

	// AdapterID is the identifier used to look up the adapter in the registry.
	AdapterID adapter.AdapterID

	// Required controls what happens when this stage fails.
	// If true, the pipeline stops immediately on failure.
	// If false, the failure is logged as a warning and execution continues.
	Required bool
}

// DefaultStages returns the standard recon pipeline in the recommended
// execution order.  Email security runs first (optional), subdomain discovery
// and HTTP probing are required, port scanning is optional, and the final
// vulnerability scan is required.
func DefaultStages() []Stage {
	return []Stage{
		{
			Name:      "Email Security",
			AdapterID: adapter.AdapterIDEmail,
			Required:  false,
		},
		{
			Name:      "Subdomain Discovery",
			AdapterID: adapter.AdapterIDSubfinder,
			Required:  true,
		},
		{
			Name:      "HTTP Probing",
			AdapterID: adapter.AdapterIDHTTPX,
			Required:  true,
		},
		{
			Name:      "Port Scanning",
			AdapterID: adapter.AdapterIDNaabu,
			Required:  false,
		},
		{
			Name:      "Vulnerability Scan",
			AdapterID: adapter.AdapterIDNuclei,
			Required:  true,
		},
	}
}
