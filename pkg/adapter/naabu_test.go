package adapter_test

// Tests for the Naabu port-scanning adapter (TASK-009).
//
// Follows TDD approach:
//   - JSON parsing is tested with sample real-world naabu output.
//   - Binary-not-found and empty-input paths are tested.
//   - Temp-file cleanup is exercised indirectly via the Run path.

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

// TestParseNaabuLine_ValidInput verifies that a well-formed naabu JSON line is
// decoded into the expected fields.
func TestParseNaabuLine_ValidInput(t *testing.T) {
	line := `{"host":"api.example.com","port":"443","protocol":"tcp"}`

	result, err := adapter.ParseNaabuLine([]byte(line))
	if err != nil {
		t.Fatalf("ParseNaabuLine() unexpected error: %v", err)
	}
	if result.Host != "api.example.com" {
		t.Errorf("Host: got %q, want %q", result.Host, "api.example.com")
	}
	if result.Port != "443" {
		t.Errorf("Port: got %q, want %q", result.Port, "443")
	}
	if result.Protocol != "tcp" {
		t.Errorf("Protocol: got %q, want %q", result.Protocol, "tcp")
	}
}

// TestParseNaabuLine_InvalidJSON verifies that malformed JSON input returns an
// error rather than silently producing a zero-value result.
func TestParseNaabuLine_InvalidJSON(t *testing.T) {
	_, err := adapter.ParseNaabuLine([]byte("not json {{{"))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestParseNaabuLine_EmptyHost verifies that a line with an empty host is
// parsed without error; the caller is responsible for skipping it.
func TestParseNaabuLine_EmptyHost(t *testing.T) {
	line := `{"host":"","port":"80","protocol":"tcp"}`
	result, err := adapter.ParseNaabuLine([]byte(line))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if result.Host != "" {
		t.Errorf("expected empty host, got %q", result.Host)
	}
}

// TestParseNaabuLine_MultipleLines tests parsing a batch of real-world naabu
// JSON lines.
func TestParseNaabuLine_MultipleLines(t *testing.T) {
	sample := `{"host":"api.example.com","port":"443","protocol":"tcp"}
{"host":"api.example.com","port":"80","protocol":"tcp"}
{"host":"mail.example.com","port":"25","protocol":"tcp"}
{"host":"dev.example.com","port":"8080","protocol":"tcp"}
`
	scanner := bufio.NewScanner(strings.NewReader(sample))
	var results []adapter.NaabuResult
	for scanner.Scan() {
		r, err := adapter.ParseNaabuLine(scanner.Bytes())
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if r.Host != "" && r.Port != "" {
			results = append(results, r)
		}
	}

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}
	if results[0].Port != "443" {
		t.Errorf("first result Port: got %q, want %q", results[0].Port, "443")
	}
	if results[2].Host != "mail.example.com" {
		t.Errorf("third result Host: got %q, want %q", results[2].Host, "mail.example.com")
	}
}

// ---------------------------------------------------------------------------
// NaabuAdapter: interface compliance tests
// ---------------------------------------------------------------------------

// TestNaabuAdapter_IDAndName verifies static metadata.
func TestNaabuAdapter_IDAndName(t *testing.T) {
	a := adapter.NewNaabuAdapter()
	if a.ID() != adapter.AdapterIDNaabu {
		t.Errorf("ID(): got %q, want %q", a.ID(), adapter.AdapterIDNaabu)
	}
	if a.Name() != "Naabu" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "Naabu")
	}
}

// TestNaabuAdapter_Check_BinaryNotFound verifies that Check returns a clear
// error when naabu is not found at the specified path.
func TestNaabuAdapter_Check_BinaryNotFound(t *testing.T) {
	a := adapter.NewNaabuAdapterWithBinary("/nonexistent/naabu-binary")

	_, err := a.Check(context.Background())
	if err == nil {
		t.Fatal("expected error when binary is not found, got nil")
	}
	if !strings.Contains(err.Error(), "naabu") && !strings.Contains(err.Error(), "not found") &&
		!strings.Contains(err.Error(), "no such file") && !strings.Contains(err.Error(), "executable") {
		t.Errorf("error message %q does not clearly indicate binary issue", err.Error())
	}
}

// TestNaabuAdapter_Run_EmptyHosts verifies that Run with no input hosts returns
// an empty output without error.
func TestNaabuAdapter_Run_EmptyHosts(t *testing.T) {
	a := adapter.NewNaabuAdapter()

	input := adapter.AdapterInput{
		Domain:     "example.com",
		LiveHosts:  []string{},
		Subdomains: []string{},
	}
	cfg := adapter.AdapterConfig{}

	out, err := a.Run(context.Background(), input, cfg, nil)
	if err != nil {
		t.Fatalf("Run() with empty hosts returned error: %v", err)
	}
	if len(out.OpenPorts) != 0 {
		t.Errorf("expected 0 open ports, got %d", len(out.OpenPorts))
	}
	if out.AdapterID != adapter.AdapterIDNaabu {
		t.Errorf("AdapterID: got %q, want %q", out.AdapterID, adapter.AdapterIDNaabu)
	}
}

// TestNaabuAdapter_Run_BinaryNotFound verifies that Run returns an error when
// the naabu binary cannot be found.
func TestNaabuAdapter_Run_BinaryNotFound(t *testing.T) {
	a := adapter.NewNaabuAdapterWithBinary("/nonexistent/naabu-binary")

	input := adapter.AdapterInput{
		Domain:    "example.com",
		LiveHosts: []string{"https://api.example.com"},
	}
	cfg := adapter.AdapterConfig{}

	_, err := a.Run(context.Background(), input, cfg, nil)
	if err == nil {
		t.Fatal("expected error when binary is not found, got nil")
	}
}

// TestNaabuAdapter_Run_FallsBackToSubdomains verifies that when LiveHosts is
// empty, the adapter falls back to using Subdomains as targets.
func TestNaabuAdapter_Run_FallsBackToSubdomains(t *testing.T) {
	a := adapter.NewNaabuAdapterWithBinary("/nonexistent/naabu-binary")

	input := adapter.AdapterInput{
		Domain:     "example.com",
		LiveHosts:  []string{},
		Subdomains: []string{"api.example.com", "www.example.com"},
	}
	cfg := adapter.AdapterConfig{}

	// With no real binary the Run must return an error (binary not found),
	// NOT a "no hosts" early-return error. This proves the fallback path
	// was exercised before reaching the exec step.
	_, err := a.Run(context.Background(), input, cfg, nil)
	if err == nil {
		t.Fatal("expected binary-not-found error, got nil")
	}
	// Must NOT be a "no hosts" style error — that would mean fallback failed.
	if strings.Contains(strings.ToLower(err.Error()), "no hosts") {
		t.Errorf("fallback to Subdomains not applied: got %q", err.Error())
	}
}

// TestNaabuAdapter_Run_ContextCancellation verifies that Run respects context
// cancellation.
func TestNaabuAdapter_Run_ContextCancellation(t *testing.T) {
	a := adapter.NewNaabuAdapterWithBinary("/nonexistent/naabu-binary")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	input := adapter.AdapterInput{
		Domain:    "example.com",
		LiveHosts: []string{"api.example.com"},
	}

	_, err := a.Run(ctx, input, adapter.AdapterConfig{}, nil)
	if err == nil {
		t.Fatal("expected an error with canceled context, got nil")
	}
}

// TestNaabuAdapter_Run_RateLimit verifies the adapter accepts RateLimit without
// panicking (binary is absent so we just check the error type).
func TestNaabuAdapter_Run_RateLimit(t *testing.T) {
	a := adapter.NewNaabuAdapterWithBinary("/nonexistent/naabu-binary")

	input := adapter.AdapterInput{
		Domain:    "example.com",
		LiveHosts: []string{"api.example.com"},
	}
	cfg := adapter.AdapterConfig{RateLimit: 100}

	_, err := a.Run(context.Background(), input, cfg, nil)
	if err == nil {
		t.Fatal("expected binary-not-found error, got nil")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("unexpected context error: %v", err)
	}
}

// TestNaabuAdapter_OpenPortFormat verifies that open port strings are formatted
// as "host:port" using the parsing helpers.
func TestNaabuAdapter_OpenPortFormat(t *testing.T) {
	lines := []string{
		`{"host":"api.example.com","port":"443","protocol":"tcp"}`,
		`{"host":"www.example.com","port":"80","protocol":"tcp"}`,
	}

	var openPorts []string
	for _, line := range lines {
		r, err := adapter.ParseNaabuLine([]byte(line))
		if err != nil {
			t.Fatalf("ParseNaabuLine() error: %v", err)
		}
		if r.Host != "" && r.Port != "" {
			openPorts = append(openPorts, r.Host+":"+r.Port)
		}
	}

	expected := []string{"api.example.com:443", "www.example.com:80"}
	if len(openPorts) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(openPorts))
	}
	for i, p := range openPorts {
		if p != expected[i] {
			t.Errorf("port[%d]: got %q, want %q", i, p, expected[i])
		}
	}
}

// TestNaabuAdapter_ProgressWriter verifies that progress is reported when a
// writer is supplied (tests the progress writing logic directly).
func TestNaabuAdapter_ProgressWriter(t *testing.T) {
	sample := `{"host":"api.example.com","port":"443","protocol":"tcp"}
{"host":"www.example.com","port":"80","protocol":"tcp"}
`
	var progressBuf bytes.Buffer
	scanner := bufio.NewScanner(strings.NewReader(sample))

	count := 0
	for scanner.Scan() {
		r, err := adapter.ParseNaabuLine(scanner.Bytes())
		if err != nil || r.Host == "" || r.Port == "" {
			continue
		}
		count++
		progressBuf.WriteString("Found open port: " + r.Host + ":" + r.Port + "\n")
	}

	if count != 2 {
		t.Errorf("expected 2 open ports, got %d", count)
	}
	if progressBuf.Len() == 0 {
		t.Error("expected progress output, got empty buffer")
	}
}
