// Package adapter — Naabu port-scanning adapter (TASK-009).
//
// NaabuAdapter wraps the projectdiscovery/naabu binary to perform TCP port
// scanning on a list of live hosts (or subdomains when no live hosts are
// available).
package adapter

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// JSON result type
// ---------------------------------------------------------------------------

// NaabuResult holds the fields decoded from a single naabu JSON output line.
type NaabuResult struct {
	// Host is the hostname or IP address that was scanned.
	Host string `json:"host"`

	// Port is the open port number as a string (naabu emits it as a string
	// in -json mode).
	Port string `json:"port"`

	// Protocol is the transport protocol, typically "tcp".
	Protocol string `json:"protocol"`
}

// ParseNaabuLine decodes a single JSON line from naabu -json output into a
// NaabuResult.  It returns an error for malformed JSON; empty Host or Port
// fields in the returned struct indicate the caller should skip the result.
//
// This function is exported so that tests can exercise the parsing logic
// independently of the adapter's exec machinery.
func ParseNaabuLine(line []byte) (NaabuResult, error) {
	var r NaabuResult
	if err := json.Unmarshal(line, &r); err != nil {
		return NaabuResult{}, fmt.Errorf("naabu: parse line: %w", err)
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// NaabuAdapter
// ---------------------------------------------------------------------------

// NaabuAdapter implements the Adapter interface for the naabu binary.
type NaabuAdapter struct {
	// binaryPath overrides the default PATH lookup when non-empty.
	binaryPath string
}

// NewNaabuAdapter returns a NaabuAdapter that locates the naabu binary via
// the system PATH.
func NewNaabuAdapter() *NaabuAdapter {
	return &NaabuAdapter{}
}

// NewNaabuAdapterWithBinary returns a NaabuAdapter that uses the supplied
// absolute path for the naabu binary.  Intended for tests that need to inject
// a fake or absent binary path.
func NewNaabuAdapterWithBinary(binaryPath string) *NaabuAdapter {
	return &NaabuAdapter{binaryPath: binaryPath}
}

// ID returns the canonical adapter identifier.
func (a *NaabuAdapter) ID() AdapterID {
	return AdapterIDNaabu
}

// Name returns the human-readable name.
func (a *NaabuAdapter) Name() string {
	return "Naabu"
}

// binary returns the resolved binary path.
func (a *NaabuAdapter) binary() (string, error) {
	if a.binaryPath != "" {
		return a.binaryPath, nil
	}
	p, err := ResolveBinary("naabu") // TODO: use toolmanager
	if err != nil {
		return "", fmt.Errorf("naabu: binary not found on PATH: %w", err)
	}
	return p, nil
}

// Check verifies that the naabu binary is available and executable by running
// "naabu -version".  It returns the version string reported by naabu.
func (a *NaabuAdapter) Check(ctx context.Context) (string, error) {
	bin, err := a.binary()
	if err != nil {
		return "", fmt.Errorf("naabu: Check: %w", err)
	}

	cmd := exec.CommandContext(ctx, bin, "-version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("naabu: Check: version command failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// Run port-scans the hosts in input.LiveHosts (falling back to
// input.Subdomains when LiveHosts is empty) using naabu and returns the open
// host:port pairs.
//
// Behavior:
//   - When both LiveHosts and Subdomains are empty the function returns
//     immediately with an empty AdapterOutput (no error).
//   - Hosts are written to a temp file; the file is removed in a defer.
//   - Output is streamed line by line.
//   - Context cancellation is propagated to the underlying exec.Cmd.
func (a *NaabuAdapter) Run(ctx context.Context, input AdapterInput, cfg AdapterConfig, progressWriter io.Writer) (AdapterOutput, error) {
	// Determine the target list: prefer LiveHosts, fall back to Subdomains.
	targets := input.LiveHosts
	if len(targets) == 0 {
		targets = input.Subdomains
	}

	// Early return when there is nothing to scan.
	if len(targets) == 0 {
		return AdapterOutput{AdapterID: AdapterIDNaabu}, nil
	}

	// Resolve binary before creating any temp files so we fail fast.
	bin, err := a.binary()
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("naabu: Run: %w", err)
	}

	// Strip scheme from URLs (naabu expects bare hostnames/IPs, not URLs).
	strippedTargets := stripSchemes(targets)

	// Write hosts to a temp file.
	tmpFile, err := writeTempList("naabu-targets-*.txt", strippedTargets)
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("naabu: Run: write temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Build argument list.
	args := []string{
		"-list", tmpFile,
		"-json",
		"-silent",
	}
	if cfg.RateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(cfg.RateLimit))
	}
	if len(cfg.ExtraArgs) > 0 {
		args = append(args, cfg.ExtraArgs...)
	}

	cmd := exec.CommandContext(ctx, bin, args...)

	// Capture stdout for streaming line-by-line parsing.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("naabu: Run: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return AdapterOutput{}, fmt.Errorf("naabu: Run: start command: %w", err)
	}

	// Stream and parse output.
	out, parseErr := a.parseStream(stdout, len(strippedTargets), progressWriter)
	out.AdapterID = AdapterIDNaabu

	// Wait for process completion.
	if waitErr := cmd.Wait(); waitErr != nil {
		if ctx.Err() != nil {
			return AdapterOutput{}, ctx.Err()
		}
		// naabu may exit non-zero when no open ports are found; treat as
		// non-fatal unless there was also a parse error.
		if parseErr != nil {
			return AdapterOutput{}, fmt.Errorf("naabu: Run: %w", parseErr)
		}
	}

	return out, nil
}

// parseStream reads naabu JSON output line by line from r, populates an
// AdapterOutput, and writes progress messages.
func (a *NaabuAdapter) parseStream(r io.Reader, totalHosts int, progressWriter io.Writer) (AdapterOutput, error) {
	var out AdapterOutput
	scanned := 0

	// Track which distinct hosts we've seen to report progress.
	seenHosts := make(map[string]struct{})

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		result, err := ParseNaabuLine(line)
		if err != nil {
			// Skip unparseable lines.
			continue
		}
		if result.Host == "" || result.Port == "" {
			continue
		}

		portStr := result.Host + ":" + result.Port
		out.OpenPorts = append(out.OpenPorts, portStr)
		scanned++

		if _, seen := seenHosts[result.Host]; !seen {
			seenHosts[result.Host] = struct{}{}
		}

		if progressWriter != nil {
			fmt.Fprintf(progressWriter, "Scanned %d hosts, found %d open ports... (latest: %s)\n",
				len(seenHosts), scanned, portStr)
		}
	}

	return out, scanner.Err()
}

// stripSchemes removes http:// and https:// prefixes from URLs so that naabu
// receives bare hostnames.  Path components and query strings are also removed.
func stripSchemes(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		host := u
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		// Remove any path/query after the first slash.
		if idx := strings.IndexByte(host, '/'); idx != -1 {
			host = host[:idx]
		}
		if host != "" {
			out = append(out, host)
		}
	}
	return out
}

func init() {
	Register(&NaabuAdapter{})
}
