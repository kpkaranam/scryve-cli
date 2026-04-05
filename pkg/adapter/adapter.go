// Package adapter defines the core extension point for all security-tool
// integrations in Scryve. Every tool (subfinder, httpx, naabu, nuclei, …) is
// wrapped behind the Adapter interface so the pipeline can drive them in a
// uniform way: check availability, stream progress, and receive structured
// output without knowing the details of the underlying binary.
package adapter

import (
	"context"
	"io"
	"time"
)

// ---------------------------------------------------------------------------
// Identifier type and constants
// ---------------------------------------------------------------------------

// AdapterID is the canonical string identifier for a registered adapter.
// It is used as the key in the global registry, in config files, and in log
// output so that spellings are always consistent.
type AdapterID string

const (
	// AdapterIDSubfinder identifies the subfinder subdomain-enumeration adapter.
	AdapterIDSubfinder AdapterID = "subfinder"

	// AdapterIDHTTPX identifies the httpx HTTP-probing adapter.
	AdapterIDHTTPX AdapterID = "httpx"

	// AdapterIDNaabu identifies the naabu port-scanning adapter.
	AdapterIDNaabu AdapterID = "naabu"

	// AdapterIDNuclei identifies the nuclei vulnerability-scanning adapter.
	AdapterIDNuclei AdapterID = "nuclei"

	// AdapterIDEmail identifies the email-notification adapter (not a security
	// tool but shares the same lifecycle as real adapters).
	AdapterIDEmail AdapterID = "email"
)

// ---------------------------------------------------------------------------
// Input / Output / Finding types
// ---------------------------------------------------------------------------

// AdapterInput carries the data that flows into an adapter at runtime.
// Earlier pipeline stages populate the slices so later adapters have access
// to accumulated discoveries without re-doing previous work.
type AdapterInput struct {
	// Domain is the root domain that the entire scan targets (e.g. "example.com").
	Domain string

	// Subdomains is the list of subdomains discovered by earlier pipeline stages.
	// For example, subfinder fills this in so httpx can probe each one.
	Subdomains []string

	// LiveHosts is the list of URLs confirmed to be responding (from httpx).
	// Naabu and nuclei consume this slice.
	LiveHosts []string

	// OpenPorts is the list of "host:port" strings found by naabu.
	// Nuclei and reporting adapters consume this slice.
	OpenPorts []string
}

// RawFinding is a single unprocessed result emitted by a tool.
// It preserves the original tool output as a free-form map so the finding
// normalization layer can process it later without losing information.
type RawFinding struct {
	// ToolName is the adapter that produced this finding (matches AdapterID).
	ToolName string

	// ToolOutput is the raw key-value data from the tool (e.g. a JSON object
	// decoded into a map).
	ToolOutput map[string]interface{}
}

// AdapterOutput is the structured result returned by Adapter.Run.
// It mirrors AdapterInput so that the pipeline can pass an output directly as
// the input to the next stage after merging the relevant slices.
type AdapterOutput struct {
	// AdapterID identifies which adapter produced this output.
	AdapterID AdapterID

	// RawFindings contains every unprocessed result emitted by the tool.
	RawFindings []RawFinding

	// Subdomains is the (possibly extended) list of discovered subdomains.
	Subdomains []string

	// LiveHosts is the (possibly extended) list of confirmed live URLs.
	LiveHosts []string

	// OpenPorts is the (possibly extended) list of open host:port pairs.
	OpenPorts []string
}

// ---------------------------------------------------------------------------
// AdapterConfig
// ---------------------------------------------------------------------------

// AdapterConfig carries per-adapter runtime settings. Values here override
// any defaults built into the adapter.
type AdapterConfig struct {
	// BinaryPath is the absolute path to the tool binary.  When empty the
	// adapter must locate the binary on $PATH itself.
	BinaryPath string

	// RateLimit is the maximum number of requests per second the tool should
	// emit. 0 means use the adapter's built-in default.
	RateLimit int

	// Timeout is the maximum time this adapter may run. 0 means no timeout.
	Timeout time.Duration

	// ExtraArgs are additional CLI flags appended verbatim to the tool's
	// invocation. Use sparingly – prefer explicit fields over raw flags.
	ExtraArgs []string

	// OutputDir is the directory where the adapter may write intermediate
	// artifacts (JSON output files, temp data, …).
	OutputDir string
}

// ---------------------------------------------------------------------------
// Adapter interface
// ---------------------------------------------------------------------------

// Adapter is the primary extension point for all tool integrations.
// Implementing this interface is all that is required to plug a new tool into
// the Scryve pipeline.
type Adapter interface {
	// ID returns the canonical identifier for this adapter.  It must be
	// unique across all registered adapters.
	ID() AdapterID

	// Name returns a human-readable display name (e.g. "subfinder").
	Name() string

	// Check verifies that the adapter's underlying tool is installed and
	// functional.  It returns the tool's version string on success so callers
	// can log it for reproducibility.
	Check(ctx context.Context) (version string, err error)

	// Run executes the tool against the supplied input, streams progress
	// messages to progressWriter (which may be nil), and returns structured
	// output.  Implementations must honor context cancellation and return
	// ctx.Err() when the context is done.
	Run(ctx context.Context, input AdapterInput, cfg AdapterConfig, progressWriter io.Writer) (AdapterOutput, error)
}
