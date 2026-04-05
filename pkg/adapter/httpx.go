// Package adapter — httpx HTTP-probing adapter (TASK-008).
//
// HTTPXAdapter wraps the projectdiscovery/httpx binary to probe a list of
// subdomains, detect live hosts, extract titles and technology stacks, and
// identify CDN usage.
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

// HTTPXResult holds the fields decoded from a single httpx JSON output line.
// Only the fields used by Scryve are mapped; additional httpx fields are
// silently ignored via the json decoder's default behavior.
type HTTPXResult struct {
	// URL is the fully qualified URL that responded (e.g. "https://api.example.com").
	URL string `json:"url"`

	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`

	// Title is the HTML page title extracted by httpx.
	Title string `json:"title"`

	// Technologies is the list of detected technology names (e.g. ["nginx","Go"]).
	Technologies []string `json:"technologies"`

	// CDN is true when httpx identified the host as behind a CDN.
	CDN bool `json:"cdn"`

	// CDNName is the CDN provider name when CDN is true (e.g. "cloudflare").
	CDNName string `json:"cdn_name"`
}

// ParseHTTPXLine decodes a single JSON line from httpx -json output into an
// HTTPXResult. It returns an error for malformed JSON; an empty URL field in
// the returned struct indicates the caller should skip this result.
//
// This function is exported so that tests can exercise the parsing logic
// independently of the adapter's exec machinery.
func ParseHTTPXLine(line []byte) (HTTPXResult, error) {
	var r HTTPXResult
	if err := json.Unmarshal(line, &r); err != nil {
		return HTTPXResult{}, fmt.Errorf("httpx: parse line: %w", err)
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// HTTPXAdapter
// ---------------------------------------------------------------------------

// HTTPXAdapter implements the Adapter interface for the httpx binary.
type HTTPXAdapter struct {
	// binaryPath overrides the default PATH lookup when non-empty.
	binaryPath string
}

// NewHTTPXAdapter returns an HTTPXAdapter that locates the httpx binary via
// the system PATH.
func NewHTTPXAdapter() *HTTPXAdapter {
	return &HTTPXAdapter{}
}

// NewHTTPXAdapterWithBinary returns an HTTPXAdapter that uses the supplied
// absolute path for the httpx binary.  This constructor is intended for tests
// that need to inject a fake or absent binary path.
func NewHTTPXAdapterWithBinary(binaryPath string) *HTTPXAdapter {
	return &HTTPXAdapter{binaryPath: binaryPath}
}

// ID returns the canonical adapter identifier.
func (a *HTTPXAdapter) ID() AdapterID {
	return AdapterIDHTTPX
}

// Name returns the human-readable name.
func (a *HTTPXAdapter) Name() string {
	return "httpx"
}

// binary returns the resolved binary path: the configured override when set,
// otherwise the result of ResolveBinary("httpx") // TODO: use toolmanager.
func (a *HTTPXAdapter) binary() (string, error) {
	if a.binaryPath != "" {
		return a.binaryPath, nil
	}
	p, err := ResolveBinary("httpx") // TODO: use toolmanager
	if err != nil {
		return "", fmt.Errorf("httpx: binary not found on PATH: %w", err)
	}
	return p, nil
}

// Check verifies that the httpx binary is available and executable by running
// "httpx -version".  It returns the version string reported by httpx.
func (a *HTTPXAdapter) Check(ctx context.Context) (string, error) {
	bin, err := a.binary()
	if err != nil {
		return "", fmt.Errorf("httpx: Check: %w", err)
	}

	cmd := exec.CommandContext(ctx, bin, "-version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("httpx: Check: version command failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// Run probes the subdomains listed in input.Subdomains using httpx and returns
// live hosts, raw findings (technology detections), and progress messages.
//
// Behavior:
//   - When input.Subdomains is empty the function returns immediately with an
//     empty AdapterOutput (no error).
//   - Subdomains are written to a temp file; the file is removed in a defer.
//   - Output is streamed line by line so that large result sets do not buffer
//     entirely in memory.
//   - Context cancellation is propagated to the underlying exec.Cmd.
func (a *HTTPXAdapter) Run(ctx context.Context, input AdapterInput, cfg AdapterConfig, progressWriter io.Writer) (AdapterOutput, error) {
	// Early return for empty input — nothing to probe.
	if len(input.Subdomains) == 0 {
		return AdapterOutput{AdapterID: AdapterIDHTTPX}, nil
	}

	// Resolve binary before creating any temp files so we fail fast.
	bin, err := a.binary()
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("httpx: Run: %w", err)
	}

	// Write subdomains to a temp file.
	tmpFile, err := writeTempList("httpx-targets-*.txt", input.Subdomains)
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("httpx: Run: write temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Build argument list.
	args := []string{
		"-l", tmpFile,
		"-json",
		"-silent",
		"-status-code",
		"-title",
		"-tech-detect",
		"-cdn",
	}
	if cfg.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.RateLimit))
	}
	if len(cfg.ExtraArgs) > 0 {
		args = append(args, cfg.ExtraArgs...)
	}

	cmd := exec.CommandContext(ctx, bin, args...)

	// Capture stdout for streaming line-by-line parsing.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return AdapterOutput{}, fmt.Errorf("httpx: Run: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return AdapterOutput{}, fmt.Errorf("httpx: Run: start command: %w", err)
	}

	// Stream and parse output.
	out, parseErr := a.parseStream(stdout, input.Subdomains, progressWriter)
	out.AdapterID = AdapterIDHTTPX

	// Wait for the process to finish; context cancellation is surfaced here.
	if waitErr := cmd.Wait(); waitErr != nil {
		// If the context was canceled, return the context error.
		if ctx.Err() != nil {
			return AdapterOutput{}, ctx.Err()
		}
		// httpx exits non-zero when no hosts are found; treat as non-fatal.
		// But surface genuine execution errors.
		if parseErr != nil {
			return AdapterOutput{}, fmt.Errorf("httpx: Run: %w", parseErr)
		}
	}

	return out, nil
}

// parseStream reads httpx JSON output line by line from r, populates an
// AdapterOutput, and optionally writes progress messages.
func (a *HTTPXAdapter) parseStream(r io.Reader, targets []string, progressWriter io.Writer) (AdapterOutput, error) {
	var out AdapterOutput
	total := len(targets)
	probed := 0

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		result, err := ParseHTTPXLine(line)
		if err != nil {
			// Skip unparseable lines; do not abort the entire run.
			continue
		}
		if result.URL == "" {
			continue
		}

		probed++
		out.LiveHosts = append(out.LiveHosts, result.URL)

		// Emit a finding when there is interesting technology or CDN info.
		if len(result.Technologies) > 0 || result.CDN {
			rawOutput := map[string]interface{}{
				"url":          result.URL,
				"status_code":  result.StatusCode,
				"title":        result.Title,
				"technologies": result.Technologies,
				"cdn":          result.CDN,
				"cdn_name":     result.CDNName,
			}
			out.RawFindings = append(out.RawFindings, RawFinding{
				ToolName:   "httpx",
				ToolOutput: rawOutput,
			})
		}

		if progressWriter != nil {
			fmt.Fprintf(progressWriter, "Probed %d/%d hosts... (latest: %s)\n", probed, total, result.URL)
		}
	}

	return out, scanner.Err()
}

// writeTempList writes lines to a new temp file and returns its path.
// The caller is responsible for removing the file.
func writeTempList(pattern string, lines []string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return "", err
		}
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func init() {
	Register(&HTTPXAdapter{})
}
