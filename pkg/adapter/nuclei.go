// Package adapter — Nuclei vulnerability-scanning adapter.
//
// NucleiAdapter wraps the projectdiscovery/nuclei binary to run template-based
// vulnerability scans against a list of targets and emit structured findings.
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
// Typed result structs
// ---------------------------------------------------------------------------

// NucleiClassification holds CVE/CWE and CVSS data from a nuclei template.
type NucleiClassification struct {
	// CVEID is the list of CVE identifiers associated with this finding.
	CVEID []string `json:"cve-id"`

	// CWEID is the list of CWE identifiers associated with this finding.
	CWEID []string `json:"cwe-id"`

	// CVSSScore is the CVSS base score (0.0–10.0).
	CVSSScore float64 `json:"cvss-score"`

	// CVSSMetrics is the full CVSS vector string.
	CVSSMetrics string `json:"cvss-metrics"`
}

// NucleiInfo holds the template metadata block from a nuclei JSON result.
type NucleiInfo struct {
	// Name is the human-readable template name.
	Name string `json:"name"`

	// Severity is the risk level: info, low, medium, high, critical.
	Severity string `json:"severity"`

	// Description provides a detailed explanation of the vulnerability.
	Description string `json:"description"`

	// Tags is the list of free-form labels attached to the template.
	Tags []string `json:"tags"`

	// Classification holds CVE/CWE and CVSS data.
	Classification NucleiClassification `json:"classification"`
}

// NucleiResult is the typed representation of a single nuclei JSON-lines record.
// It corresponds directly to the JSON object emitted by `nuclei -json`.
type NucleiResult struct {
	// TemplateID is the identifier of the nuclei template that matched.
	TemplateID string `json:"template-id"`

	// Info holds the template metadata.
	Info NucleiInfo `json:"info"`

	// Host is the target host (may be a URL or hostname).
	Host string `json:"host"`

	// MatchedAt is the specific URL or location where the template matched.
	MatchedAt string `json:"matched-at"`

	// Type is the protocol type used by the template (http, dns, tcp, …).
	Type string `json:"type"`

	// IP is the resolved IP address of the target.
	IP string `json:"ip"`

	// Port is the port number as a string (nuclei emits it as a string).
	Port string `json:"port"`

	// MatcherName is the name of the matcher that triggered within the template.
	MatcherName string `json:"matcher-name"`

	// ExtractedResults contains strings extracted by extractor matchers.
	ExtractedResults []string `json:"extracted-results"`

	// CurlCommand is a ready-to-run curl command reproducing the finding.
	CurlCommand string `json:"curl-command"`
}

// ParseNucleiLine decodes a single JSON line from nuclei -json output into a
// NucleiResult. It returns an error for malformed or empty JSON.
//
// This function is exported so tests can exercise the parsing logic
// independently of the adapter's exec machinery.
func ParseNucleiLine(line []byte) (*NucleiResult, error) {
	if len(line) == 0 {
		return nil, fmt.Errorf("nuclei: parse line: empty input")
	}
	var r NucleiResult
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, fmt.Errorf("nuclei: parse line: %w", err)
	}
	return &r, nil
}

// ---------------------------------------------------------------------------
// NucleiAdapter
// ---------------------------------------------------------------------------

// NucleiAdapter implements the Adapter interface for the nuclei binary.
type NucleiAdapter struct {
	// binaryPath overrides the default PATH lookup when non-empty.
	binaryPath string
}

// NewNucleiAdapter returns a NucleiAdapter that locates the nuclei binary via
// the system PATH.
func NewNucleiAdapter() *NucleiAdapter {
	return &NucleiAdapter{}
}

// NewNucleiAdapterWithBinary returns a NucleiAdapter that uses the supplied
// absolute path for the nuclei binary. This constructor is intended for tests.
func NewNucleiAdapterWithBinary(binaryPath string) *NucleiAdapter {
	return &NucleiAdapter{binaryPath: binaryPath}
}

// init registers the NucleiAdapter with the global registry so that any
// package that imports adapter can use adapter.Get(AdapterIDNuclei).
func init() {
	Register(NewNucleiAdapter())
}

// ---------------------------------------------------------------------------
// Adapter interface implementation
// ---------------------------------------------------------------------------

// ID returns AdapterIDNuclei.
func (a *NucleiAdapter) ID() AdapterID {
	return AdapterIDNuclei
}

// Name returns the human-readable display name.
func (a *NucleiAdapter) Name() string {
	return "Nuclei"
}

// binary returns the resolved binary path.
func (a *NucleiAdapter) binary() (string, error) {
	if a.binaryPath != "" {
		return a.binaryPath, nil
	}
	p, err := ResolveBinary("nuclei") // TODO: use toolmanager
	if err != nil {
		return "", fmt.Errorf("nuclei: binary not found on PATH: %w", err)
	}
	return p, nil
}

// Check verifies that the nuclei binary is available by running `nuclei -version`.
// It returns the version string reported by nuclei.
func (a *NucleiAdapter) Check(ctx context.Context) (string, error) {
	bin, err := a.binary()
	if err != nil {
		return "", fmt.Errorf("nuclei: Check: %w", err)
	}

	cmd := exec.CommandContext(ctx, bin, "-version") //nolint:gosec
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("nuclei: Check: version command failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return a.parseVersion(strings.TrimSpace(string(out))), nil
}

// Run executes nuclei against the resolved target list and returns raw findings.
//
// Target selection priority:
//  1. input.LiveHosts (URLs confirmed live by httpx)
//  2. input.Subdomains (fallback when LiveHosts is empty)
//  3. input.OpenPorts (fallback when both LiveHosts and Subdomains are empty)
//
// When all three slices are empty, Run returns immediately with an empty output.
//
// The command built is:
//
//	nuclei -l <targets-file> -json -silent -nc [-rl <rate>] [-timeout <secs>] [extra args…]
func (a *NucleiAdapter) Run(ctx context.Context, input AdapterInput, cfg AdapterConfig, progressWriter io.Writer) (AdapterOutput, error) {
	targets := a.resolveTargets(input)

	// Early return for empty input — nothing to scan.
	if len(targets) == 0 {
		return AdapterOutput{AdapterID: AdapterIDNuclei}, nil
	}

	// Apply cfg.Timeout as an additional deadline if requested.
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	// Resolve binary before creating any temp files so we fail fast.
	bin, err := a.binary()
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("nuclei: Run: %w", err)
	}

	// Write targets to a temp file.
	tmpFile, err := writeTempList("nuclei-targets-*.txt", targets)
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("nuclei: Run: write temp file: %w", err)
	}
	defer os.Remove(tmpFile) //nolint:errcheck

	args := a.buildArgs(tmpFile, cfg)
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("nuclei: Run: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return AdapterOutput{}, fmt.Errorf("nuclei: Run: start command: %w", err)
	}

	// Stream and parse output while the process runs.
	rawFindings, parseErr := a.parseStream(stdout, progressWriter)

	// Wait for the process to finish.
	waitErr := cmd.Wait()

	// Context cancellation takes priority over other errors.
	if ctx.Err() != nil {
		return AdapterOutput{}, ctx.Err()
	}

	// nuclei may exit non-zero on certain conditions; treat as non-fatal unless
	// we got a parse error and no results.
	if waitErr != nil && len(rawFindings) == 0 && parseErr != nil {
		return AdapterOutput{}, fmt.Errorf("nuclei: Run: %w", waitErr)
	}

	return AdapterOutput{
		AdapterID:   AdapterIDNuclei,
		RawFindings: rawFindings,
	}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// resolveTargets returns the first non-empty slice from LiveHosts, Subdomains,
// or OpenPorts, in that priority order.
func (a *NucleiAdapter) resolveTargets(input AdapterInput) []string {
	if len(input.LiveHosts) > 0 {
		return input.LiveHosts
	}
	if len(input.Subdomains) > 0 {
		return input.Subdomains
	}
	return input.OpenPorts
}

// buildArgs constructs the CLI argument slice for a nuclei scan.
func (a *NucleiAdapter) buildArgs(targetsFile string, cfg AdapterConfig) []string {
	args := []string{
		"-l", targetsFile,
		"-json",
		"-silent",
		"-nc", // no-color: avoids ANSI escape codes in output
	}

	if cfg.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.RateLimit))
	}

	if len(cfg.ExtraArgs) > 0 {
		args = append(args, cfg.ExtraArgs...)
	}

	return args
}

// parseStream reads nuclei JSON-lines output from r, builds RawFindings, and
// emits progress messages when progressWriter is non-nil.
func (a *NucleiAdapter) parseStream(r io.Reader, progressWriter io.Writer) ([]RawFinding, error) {
	var rawFindings []RawFinding
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Decode into a generic map to preserve all fields for RawFindings.
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			// Skip lines that are not valid JSON (nuclei also emits status lines).
			continue
		}

		// Skip records without a template-id or host — they're status messages.
		templateID, _ := raw["template-id"].(string)
		host, _ := raw["host"].(string)
		if templateID == "" || host == "" {
			continue
		}

		rawFindings = append(rawFindings, RawFinding{
			ToolName:   string(AdapterIDNuclei),
			ToolOutput: raw,
		})

		if progressWriter != nil {
			fmt.Fprintf(progressWriter, "[nuclei] %s → %s\n", templateID, host)
		}
	}

	return rawFindings, scanner.Err()
}

// parseVersion extracts the first version token (e.g. "v3.1.0") from the raw
// output of `nuclei -version`.
func (a *NucleiAdapter) parseVersion(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, token := range strings.Fields(line) {
			if len(token) > 1 && token[0] == 'v' && token[1] >= '0' && token[1] <= '9' {
				return token
			}
		}
		return line
	}
	return raw
}
