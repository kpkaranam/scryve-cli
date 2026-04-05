// Package cmd_test — E2E test helpers for the scan command.
//
// These utilities are shared across E2E test files to reduce boilerplate and
// keep test fixtures consistent. They follow the Arrange step of AAA.
package cmd_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/finding"
	"github.com/scryve/scryve/pkg/pipeline"
)

// ---------------------------------------------------------------------------
// PipelineResult builders
// ---------------------------------------------------------------------------

// findingSpec describes a single mock finding for use in buildMockPipelineResult.
type findingSpec struct {
	title    string
	severity finding.Severity
	host     string
	tool     string
}

// buildMockPipelineResult constructs a *pipeline.PipelineResult populated with
// the given finding specs and domain. StartedAt and CompletedAt are set to fixed
// values so tests are deterministic.
func buildMockPipelineResult(domain string, specs []findingSpec) *pipeline.PipelineResult {
	now := time.Date(2026, 3, 29, 12, 0, 0, 0, time.UTC)
	findings := make([]finding.Finding, 0, len(specs))
	for i, s := range specs {
		tool := s.tool
		if tool == "" {
			tool = "nuclei"
		}
		host := s.host
		if host == "" {
			host = domain
		}
		findings = append(findings, finding.Finding{
			ID:        fmt.Sprintf("finding-%d", i+1),
			Title:     s.title,
			Severity:  s.severity,
			Host:      host,
			Tool:      tool,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
	return &pipeline.PipelineResult{
		Domain:      domain,
		StartedAt:   now,
		CompletedAt: now.Add(5 * time.Second),
		Findings:    findings,
		Stages: []pipeline.StageResult{
			{
				Stage:    pipeline.Stage{Name: "Subdomain Discovery", AdapterID: adapter.AdapterIDSubfinder},
				Status:   "completed",
				Duration: 1 * time.Second,
				Stats:    map[string]int{"subdomains": 2, "live_hosts": 0, "open_ports": 0, "findings": 0},
			},
			{
				Stage:    pipeline.Stage{Name: "Vulnerability Scan", AdapterID: adapter.AdapterIDNuclei},
				Status:   "completed",
				Duration: 4 * time.Second,
				Stats:    map[string]int{"subdomains": 0, "live_hosts": 0, "open_ports": 0, "findings": len(specs)},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Mock pipeline runner
// ---------------------------------------------------------------------------

// mockPipelineRun builds a pipeline using mock adapters and executes it against
// the given domain. It returns the PipelineResult with findings from mockFindings.
// It is intentionally thin so tests control exactly what findings appear.
func mockPipelineRun(t *testing.T, domain string, mockFindings []adapter.RawFinding) *pipeline.PipelineResult {
	t.Helper()

	nucleiMock := &adapter.MockAdapter{
		MockID:       adapter.AdapterIDNuclei,
		MockName:     "nuclei",
		MockFindings: mockFindings,
	}
	subfinderMock := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"api." + domain, "www." + domain},
	}

	reg := adapter.NewRegistry()
	reg.Register(subfinderMock)
	reg.Register(nucleiMock)

	stages := []pipeline.Stage{
		{Name: "Subdomain Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "Vulnerability Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	result, err := p.Run(context.Background(), domain, nil)
	if err != nil {
		t.Fatalf("mockPipelineRun: pipeline returned error: %v", err)
	}
	return result
}

// ---------------------------------------------------------------------------
// Temp directory and file helpers
// ---------------------------------------------------------------------------

// createTempOutputDir creates a temp directory for report output files and
// returns its path. The directory is automatically removed when the test ends.
func createTempOutputDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// tempReportPath returns a file path inside a new temp dir for the given filename.
func tempReportPath(t *testing.T, filename string) string {
	t.Helper()
	dir := createTempOutputDir(t)
	return filepath.Join(dir, filename)
}

// assertFileExists fails the test if path does not exist or cannot be stat'd.
func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected file to exist at %q, but it does not", path)
	} else if err != nil {
		t.Errorf("stat %q: %v", path, err)
	}
}

// assertFileNotEmpty fails the test if path is empty (zero bytes).
func assertFileNotEmpty(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Errorf("stat %q: %v", path, err)
		return
	}
	if info.Size() == 0 {
		t.Errorf("expected %q to be non-empty, but file is 0 bytes", path)
	}
}

// readFileContent reads the entire content of path and returns it as a string.
// Fails the test immediately if the file cannot be read.
func readFileContent(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFileContent(%q): %v", path, err)
	}
	return string(data)
}
