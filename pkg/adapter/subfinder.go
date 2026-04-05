package adapter

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// ---------------------------------------------------------------------------
// SubfinderAdapter
// ---------------------------------------------------------------------------

// SubfinderAdapter integrates the ProjectDiscovery subfinder binary with the
// Scryve pipeline.  It enumerates subdomains for a target domain by invoking
// the external subfinder binary and parsing its JSON-lines output.
//
// Zero value is not usable — use NewSubfinderAdapter or the globally registered
// instance obtained via adapter.Get(AdapterIDSubfinder).
type SubfinderAdapter struct{}

// NewSubfinderAdapter returns a ready-to-use *SubfinderAdapter.
func NewSubfinderAdapter() *SubfinderAdapter {
	return &SubfinderAdapter{}
}

// init registers the SubfinderAdapter with the global registry so that any
// package that imports adapter (directly or transitively) can use
// adapter.Get(AdapterIDSubfinder) without additional wiring.
func init() {
	Register(NewSubfinderAdapter())
}

// ---------------------------------------------------------------------------
// Adapter interface implementation
// ---------------------------------------------------------------------------

// ID returns AdapterIDSubfinder.
func (a *SubfinderAdapter) ID() AdapterID {
	return AdapterIDSubfinder
}

// Name returns the human-readable display name.
func (a *SubfinderAdapter) Name() string {
	return "Subfinder"
}

// Check runs `subfinder -version` and returns the parsed version string.
// It uses the default binary discovery (PATH lookup unless cfg.BinaryPath is
// set).  Check is a convenience wrapper over CheckWithConfig using an empty
// config.
func (a *SubfinderAdapter) Check(ctx context.Context) (string, error) {
	return a.CheckWithConfig(ctx, AdapterConfig{})
}

// CheckWithConfig runs `<binary> -version` using the binary path from cfg (or
// PATH if cfg.BinaryPath is empty) and returns the version string extracted
// from the output.
func (a *SubfinderAdapter) CheckWithConfig(ctx context.Context, cfg AdapterConfig) (string, error) {
	bin := a.resolveBinary(cfg)
	cmd := exec.CommandContext(ctx, bin, "-version") //nolint:gosec
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("subfinder check: %w", err)
	}
	return a.parseVersion(string(out)), nil
}

// Run executes subfinder against input.Domain and returns the discovered
// subdomains as structured AdapterOutput.
//
// The command built is:
//
//	subfinder -d <domain> -json -silent [-rl <rate>] [extra args…]
//
// cfg.Timeout (when > 0) is applied as an additional context deadline on top of
// any deadline already present in ctx.  cfg.BinaryPath overrides PATH lookup.
func (a *SubfinderAdapter) Run(ctx context.Context, input AdapterInput, cfg AdapterConfig, progressWriter io.Writer) (AdapterOutput, error) {
	// Apply cfg.Timeout as an additional deadline if requested.
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	args := a.buildArgs(input.Domain, cfg)
	bin := a.resolveBinary(cfg)

	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("subfinder: create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return AdapterOutput{}, fmt.Errorf("subfinder: start: %w", err)
	}

	// Parse JSON lines from stdout while the process runs.
	subdomains, rawFindings, parseErr := a.parseOutput(stdout)

	// Wait for the process to exit.
	waitErr := cmd.Wait()

	// If the context was canceled or timed out, surface that error first.
	if ctx.Err() != nil {
		return AdapterOutput{}, ctx.Err()
	}

	// A non-zero exit code from subfinder is treated as an error only if we
	// also failed to collect any results (the binary may exit non-zero on empty
	// results but still emit valid JSON lines).
	if waitErr != nil && len(subdomains) == 0 {
		return AdapterOutput{}, fmt.Errorf("subfinder: %w", waitErr)
	}

	_ = parseErr // JSON parse errors per-line are silently skipped

	if progressWriter != nil {
		fmt.Fprintf(progressWriter, "Found %d subdomains for %s\n", len(subdomains), input.Domain)
	}

	return AdapterOutput{
		AdapterID:   AdapterIDSubfinder,
		Subdomains:  subdomains,
		RawFindings: rawFindings,
	}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// resolveBinary returns cfg.BinaryPath if set, otherwise "subfinder" (relying
// on PATH resolution by exec.Command).
func (a *SubfinderAdapter) resolveBinary(cfg AdapterConfig) string {
	if cfg.BinaryPath != "" {
		return cfg.BinaryPath
	}
	return "subfinder"
}

// buildArgs constructs the CLI argument slice for a scan invocation.
func (a *SubfinderAdapter) buildArgs(domain string, cfg AdapterConfig) []string {
	args := []string{"-d", domain, "-json", "-silent"}

	if cfg.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", cfg.RateLimit))
	}

	if len(cfg.ExtraArgs) > 0 {
		args = append(args, cfg.ExtraArgs...)
	}

	return args
}

// parseOutput reads JSON lines from r, extracting unique subdomains and
// building RawFindings.  Lines that are not valid JSON are silently skipped.
func (a *SubfinderAdapter) parseOutput(r io.Reader) (subdomains []string, rawFindings []RawFinding, err error) {
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Decode into a generic map to preserve all fields for RawFindings.
		var raw map[string]interface{}
		if jsonErr := json.Unmarshal([]byte(line), &raw); jsonErr != nil {
			// Skip lines that are not valid JSON.
			continue
		}

		// Extract the host field.
		host, _ := raw["host"].(string)
		if host == "" {
			continue
		}

		rawFindings = append(rawFindings, RawFinding{
			ToolName:   string(AdapterIDSubfinder),
			ToolOutput: raw,
		})

		if !seen[host] {
			seen[host] = true
			subdomains = append(subdomains, host)
		}
	}

	return subdomains, rawFindings, scanner.Err()
}

// parseVersion extracts the first version token (e.g. "v2.6.3") from the raw
// output of `subfinder -version`.  The subfinder binary writes to stderr and
// typically outputs "Current Version: v2.6.3".
func (a *SubfinderAdapter) parseVersion(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Look for a token starting with "v" followed by a digit.
		for _, token := range strings.Fields(line) {
			if len(token) > 1 && token[0] == 'v' && token[1] >= '0' && token[1] <= '9' {
				return token
			}
		}
		// Fallback: return the whole line if no version token found.
		return line
	}
	return raw
}
