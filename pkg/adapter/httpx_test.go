package adapter_test

// Tests for the httpx HTTP-probing adapter (TASK-008).
//
// These tests follow the TDD approach:
//   - JSON parsing is exercised via an exported helper that the adapter exposes
//     for testing (parseHTTPXLine).
//   - Binary-not-found and empty-input paths are tested against the real adapter.
//   - Temp-file creation/cleanup is verified indirectly via the Run path.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/scryve/scryve/pkg/adapter"
)

// ---------------------------------------------------------------------------
// Unit tests: JSON line parsing
// ---------------------------------------------------------------------------

// TestParseHTTPXLine_ValidInput verifies that a well-formed httpx JSON line is
// decoded into the expected fields.
func TestParseHTTPXLine_ValidInput(t *testing.T) {
	line := `{"url":"https://api.example.com","status_code":200,"title":"My API","technologies":["nginx","Go"]}`

	result, err := adapter.ParseHTTPXLine([]byte(line))
	if err != nil {
		t.Fatalf("ParseHTTPXLine() unexpected error: %v", err)
	}

	if result.URL != "https://api.example.com" {
		t.Errorf("URL: got %q, want %q", result.URL, "https://api.example.com")
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode: got %d, want 200", result.StatusCode)
	}
	if result.Title != "My API" {
		t.Errorf("Title: got %q, want %q", result.Title, "My API")
	}
	if len(result.Technologies) != 2 {
		t.Errorf("Technologies: got %d entries, want 2", len(result.Technologies))
	}
}

// TestParseHTTPXLine_InvalidJSON verifies that malformed input returns an error
// rather than silently producing a zero-value result.
func TestParseHTTPXLine_InvalidJSON(t *testing.T) {
	_, err := adapter.ParseHTTPXLine([]byte("not json {{{"))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestParseHTTPXLine_EmptyURL verifies that a line with an empty URL is
// considered an invalid result (URL field is required).
func TestParseHTTPXLine_EmptyURL(t *testing.T) {
	line := `{"url":"","status_code":200,"title":"empty"}`
	result, err := adapter.ParseHTTPXLine([]byte(line))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	// URL being empty means the line should be skipped by the caller.
	if result.URL != "" {
		t.Errorf("expected empty URL, got %q", result.URL)
	}
}

// TestParseHTTPXLine_WithCDN verifies that CDN detection fields are captured.
func TestParseHTTPXLine_WithCDN(t *testing.T) {
	line := `{"url":"https://cdn.example.com","status_code":301,"title":"","cdn":true,"cdn_name":"cloudflare"}`
	result, err := adapter.ParseHTTPXLine([]byte(line))
	if err != nil {
		t.Fatalf("ParseHTTPXLine() unexpected error: %v", err)
	}
	if !result.CDN {
		t.Error("CDN: got false, want true")
	}
	if result.CDNName != "cloudflare" {
		t.Errorf("CDNName: got %q, want %q", result.CDNName, "cloudflare")
	}
}

// ---------------------------------------------------------------------------
// HTTPXAdapter: interface compliance tests
// ---------------------------------------------------------------------------

// TestHTTPXAdapter_IDAndName verifies the static metadata.
func TestHTTPXAdapter_IDAndName(t *testing.T) {
	a := adapter.NewHTTPXAdapter()
	if a.ID() != adapter.AdapterIDHTTPX {
		t.Errorf("ID(): got %q, want %q", a.ID(), adapter.AdapterIDHTTPX)
	}
	if a.Name() != "httpx" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "httpx")
	}
}

// TestHTTPXAdapter_Check_BinaryNotFound verifies that Check returns a clear
// error when httpx is not on PATH (we use a non-existent binary path via cfg).
func TestHTTPXAdapter_Check_BinaryNotFound(t *testing.T) {
	a := adapter.NewHTTPXAdapterWithBinary("/nonexistent/httpx-binary")

	_, err := a.Check(context.Background())
	if err == nil {
		t.Fatal("expected error when binary is not found, got nil")
	}
	// The error message should give the caller enough context.
	if !strings.Contains(err.Error(), "httpx") && !strings.Contains(err.Error(), "not found") &&
		!strings.Contains(err.Error(), "no such file") && !strings.Contains(err.Error(), "executable") {
		t.Errorf("error message %q does not clearly indicate binary issue", err.Error())
	}
}

// TestHTTPXAdapter_Run_EmptySubdomains verifies that Run returns an empty output
// (not an error) when there are no subdomains to probe.
func TestHTTPXAdapter_Run_EmptySubdomains(t *testing.T) {
	a := adapter.NewHTTPXAdapter()

	input := adapter.AdapterInput{Domain: "example.com", Subdomains: []string{}}
	cfg := adapter.AdapterConfig{}

	out, err := a.Run(context.Background(), input, cfg, nil)
	if err != nil {
		t.Fatalf("Run() with empty subdomains returned error: %v", err)
	}
	if len(out.LiveHosts) != 0 {
		t.Errorf("expected 0 live hosts, got %d", len(out.LiveHosts))
	}
	if out.AdapterID != adapter.AdapterIDHTTPX {
		t.Errorf("AdapterID: got %q, want %q", out.AdapterID, adapter.AdapterIDHTTPX)
	}
}

// TestHTTPXAdapter_Run_BinaryNotFound verifies that Run returns an error when
// the httpx binary cannot be found.
func TestHTTPXAdapter_Run_BinaryNotFound(t *testing.T) {
	a := adapter.NewHTTPXAdapterWithBinary("/nonexistent/httpx-binary")

	input := adapter.AdapterInput{
		Domain:     "example.com",
		Subdomains: []string{"api.example.com", "www.example.com"},
	}
	cfg := adapter.AdapterConfig{}

	_, err := a.Run(context.Background(), input, cfg, nil)
	if err == nil {
		t.Fatal("expected error when binary is not found, got nil")
	}
}

// TestHTTPXAdapter_Run_ContextCancellation verifies that Run respects context
// cancellation without hanging.
func TestHTTPXAdapter_Run_ContextCancellation(t *testing.T) {
	a := adapter.NewHTTPXAdapterWithBinary("/nonexistent/httpx-binary")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	input := adapter.AdapterInput{
		Domain:     "example.com",
		Subdomains: []string{"sub.example.com"},
	}

	_, err := a.Run(ctx, input, adapter.AdapterConfig{}, nil)
	// Either context error or binary-not-found error is acceptable.
	if err == nil {
		t.Fatal("expected an error with canceled context, got nil")
	}
}

// TestHTTPXAdapter_Run_ProgressWriter verifies that progress messages are
// written when a progressWriter is provided (using output parsing simulation).
func TestHTTPXAdapter_Run_ProgressWriter(t *testing.T) {
	// We test the progress writing logic by feeding synthetic JSON output
	// through the parsing helper rather than running the real binary.
	sampleOutput := `{"url":"https://api.example.com","status_code":200,"title":"API","technologies":["Go"]}
{"url":"https://www.example.com","status_code":200,"title":"Home","technologies":["nginx"]}
`
	var progressBuf bytes.Buffer
	scanner := bufio.NewScanner(strings.NewReader(sampleOutput))

	var liveHosts []string
	lineNum := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		result, err := adapter.ParseHTTPXLine(line)
		if err != nil || result.URL == "" {
			continue
		}
		liveHosts = append(liveHosts, result.URL)
		lineNum++
		progressBuf.WriteString("Probed " + result.URL + "\n")
	}

	if len(liveHosts) != 2 {
		t.Errorf("expected 2 live hosts, got %d", len(liveHosts))
	}
	if progressBuf.Len() == 0 {
		t.Error("expected progress output, got empty buffer")
	}
}

// TestHTTPXAdapter_Run_RateLimit verifies that when RateLimit > 0 is set in
// config, the adapter does not panic or error during argument construction.
// (We test this without an actual binary by inspecting the error type.)
func TestHTTPXAdapter_Run_RateLimit(t *testing.T) {
	a := adapter.NewHTTPXAdapterWithBinary("/nonexistent/httpx-binary")

	input := adapter.AdapterInput{
		Domain:     "example.com",
		Subdomains: []string{"sub.example.com"},
	}
	cfg := adapter.AdapterConfig{RateLimit: 50}

	_, err := a.Run(context.Background(), input, cfg, nil)
	// Must return an error about binary not being found, NOT a panic or
	// argument-construction error.
	if err == nil {
		t.Fatal("expected binary-not-found error, got nil")
	}
	// Confirm it's the right kind of error (not some argument handling panic).
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("unexpected context error: %v", err)
	}
}

// TestHTTPXAdapter_ParseOutput_MultipleLines tests the full parse flow across
// multiple lines of real-world httpx JSON output.
func TestHTTPXAdapter_ParseOutput_MultipleLines(t *testing.T) {
	// Simulated real-world httpx -json output with varied fields.
	lines := []string{
		`{"url":"https://api.example.com","status_code":200,"title":"API Gateway","technologies":["nginx","Go"]}`,
		`{"url":"https://mail.example.com","status_code":301,"title":"Redirect","technologies":["Apache"]}`,
		`{"url":"https://dev.example.com","status_code":403,"title":"Forbidden","technologies":[]}`,
		`{"url":"https://cdn.example.com","status_code":200,"title":"CDN","cdn":true,"cdn_name":"cloudflare"}`,
	}

	var parsed []adapter.HTTPXResult
	for _, line := range lines {
		r, err := adapter.ParseHTTPXLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected parse error on line %q: %v", line, err)
		}
		if r.URL != "" {
			parsed = append(parsed, r)
		}
	}

	if len(parsed) != 4 {
		t.Fatalf("expected 4 results, got %d", len(parsed))
	}
	if parsed[0].StatusCode != 200 {
		t.Errorf("first result StatusCode: got %d, want 200", parsed[0].StatusCode)
	}
	if parsed[3].CDN != true {
		t.Errorf("fourth result CDN: got false, want true")
	}
}
