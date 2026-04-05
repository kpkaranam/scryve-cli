// Package cmd_test — end-to-end integration tests for the scan command.
//
// These tests exercise the full scan flow: from pipeline result construction
// using mock adapters, through compliance mapping, to report generation and
// file output.
//
// Because the scan command's pipeline is currently a stub (TODO sprint-2), the
// E2E tests cover two complementary paths:
//
//  1. Report generation path: pre-built PipelineResult values are passed
//     directly to report.GenerateHTML / report.GenerateJSON. This validates
//     the complete output pipeline without requiring real tool binaries.
//
//  2. CLI invocation path: the cobra root command is invoked with real
//     arguments and the stub-mode output is verified against expected file
//     content, format inference, and error handling.
//
//  3. Mock adapter pipeline path: the pipeline package is exercised with
//     adapter.MockAdapter instances to verify findings flow end-to-end from
//     mock tool output through normalisation to the final report.
package cmd_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/scryve/scryve/cmd"
	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/compliance"
	"github.com/scryve/scryve/pkg/finding"
	"github.com/scryve/scryve/pkg/report"
)

// ---------------------------------------------------------------------------
// TestE2E_ScanCommand_HTMLReport
// ---------------------------------------------------------------------------

// TestE2E_ScanCommand_HTMLReport verifies that the report generation path
// produces an HTML file that contains the domain name, grade, and finding titles.
func TestE2E_ScanCommand_HTMLReport(t *testing.T) {
	// Arrange
	const domain = "e2e-html.example.com"
	outputPath := tempReportPath(t, "report.html")

	pipelineResult := buildMockPipelineResult(domain, []findingSpec{
		{title: "XSS Vulnerability", severity: finding.SeverityHigh, host: domain, tool: "nuclei"},
		{title: "SQL Injection", severity: finding.SeverityHigh, host: domain, tool: "nuclei"},
	})

	// Act: generate HTML report end-to-end through the report package.
	htmlBytes, err := report.GenerateHTML(pipelineResult, nil)
	if err != nil {
		t.Fatalf("GenerateHTML returned error: %v", err)
	}
	if writeErr := os.WriteFile(outputPath, htmlBytes, 0o644); writeErr != nil {
		t.Fatalf("write HTML report to %q: %v", outputPath, writeErr)
	}

	// Assert: file must exist and be non-empty.
	assertFileExists(t, outputPath)
	assertFileNotEmpty(t, outputPath)

	content := readFileContent(t, outputPath)

	// HTML structure.
	if !strings.Contains(content, "<html") {
		t.Error("HTML report does not contain <html> tag")
	}
	if !strings.Contains(content, "</html>") {
		t.Error("HTML report does not contain closing </html> tag")
	}

	// Domain must appear in the report.
	if !strings.Contains(content, domain) {
		t.Errorf("HTML report does not contain domain %q", domain)
	}

	// Grade: 2 high findings, 0 critical → grade B.
	if !strings.Contains(content, "B") {
		t.Error("HTML report does not contain expected grade B (2 high findings)")
	}

	// Finding titles must be present in the report body.
	for _, title := range []string{"XSS Vulnerability", "SQL Injection"} {
		if !strings.Contains(content, title) {
			t.Errorf("HTML report does not contain finding title %q", title)
		}
	}
}

// ---------------------------------------------------------------------------
// TestE2E_ScanCommand_JSONReport
// ---------------------------------------------------------------------------

// TestE2E_ScanCommand_JSONReport verifies that the report generation path
// produces a valid JSON file with the expected top-level structure.
func TestE2E_ScanCommand_JSONReport(t *testing.T) {
	// Arrange
	const domain = "e2e-json.example.com"
	outputPath := tempReportPath(t, "report.json")

	pipelineResult := buildMockPipelineResult(domain, []findingSpec{
		{title: "Open Port Exposure", severity: finding.SeverityMedium, host: domain, tool: "naabu"},
	})

	// Act: generate JSON report end-to-end.
	jsonBytes, err := report.GenerateJSON(pipelineResult, nil)
	if err != nil {
		t.Fatalf("GenerateJSON returned error: %v", err)
	}
	if writeErr := os.WriteFile(outputPath, jsonBytes, 0o644); writeErr != nil {
		t.Fatalf("write JSON report to %q: %v", outputPath, writeErr)
	}

	// Assert: file exists and parses as valid JSON.
	assertFileExists(t, outputPath)
	assertFileNotEmpty(t, outputPath)

	content := readFileContent(t, outputPath)

	var parsed report.JSONReport
	if unmarshalErr := json.Unmarshal([]byte(content), &parsed); unmarshalErr != nil {
		t.Fatalf("JSON report is not valid JSON: %v\ncontent:\n%s", unmarshalErr, content)
	}

	// Top-level scalar fields.
	if parsed.Domain != domain {
		t.Errorf("JSON report domain = %q, want %q", parsed.Domain, domain)
	}
	if parsed.Grade == "" {
		t.Error("JSON report grade must not be empty")
	}

	// Summary counts.
	if parsed.Summary.Total != 1 {
		t.Errorf("JSON summary.total = %d, want 1", parsed.Summary.Total)
	}
	if parsed.Summary.Medium != 1 {
		t.Errorf("JSON summary.medium = %d, want 1", parsed.Summary.Medium)
	}

	// Findings array.
	if len(parsed.Findings) != 1 {
		t.Fatalf("JSON findings count = %d, want 1", len(parsed.Findings))
	}
	f := parsed.Findings[0]
	if f.Title != "Open Port Exposure" {
		t.Errorf("finding title = %q, want %q", f.Title, "Open Port Exposure")
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("finding severity = %v, want %v", f.Severity, finding.SeverityMedium)
	}

	// Stages must be populated.
	if len(parsed.Stages) == 0 {
		t.Error("JSON report stages must not be empty")
	}

	// Compliance section must be absent when no mapper is passed.
	if parsed.Compliance != nil {
		t.Error("JSON report compliance must be nil when no mapper is provided")
	}
}

// ---------------------------------------------------------------------------
// TestE2E_ScanCommand_WithCompliance
// ---------------------------------------------------------------------------

// TestE2E_ScanCommand_WithCompliance verifies that when a compliance mapper is
// provided, both HTML and JSON reports include a populated compliance section
// with the PCI DSS framework name and at least one control result.
func TestE2E_ScanCommand_WithCompliance(t *testing.T) {
	// Arrange
	const domain = "e2e-compliance.example.com"

	pipelineResult := buildMockPipelineResult(domain, []findingSpec{
		{title: "SQL Injection", severity: finding.SeverityCritical, host: domain, tool: "nuclei"},
	})

	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error: %v", err)
	}
	complianceReporter := report.NewComplianceReporter(mapper)

	// Act: generate JSON report with compliance mapping.
	jsonBytes, jsonErr := report.GenerateJSON(pipelineResult, complianceReporter)
	if jsonErr != nil {
		t.Fatalf("GenerateJSON with compliance: %v", jsonErr)
	}

	// Act: generate HTML report with compliance mapping.
	htmlBytes, htmlErr := report.GenerateHTML(pipelineResult, complianceReporter)
	if htmlErr != nil {
		t.Fatalf("GenerateHTML with compliance: %v", htmlErr)
	}

	// Assert JSON: compliance section must be present and populated.
	var parsed report.JSONReport
	if unmarshalErr := json.Unmarshal(jsonBytes, &parsed); unmarshalErr != nil {
		t.Fatalf("JSON unmarshal: %v", unmarshalErr)
	}
	if parsed.Compliance == nil {
		t.Fatal("JSON compliance section must not be nil when mapper is provided")
	}
	if parsed.Compliance.Framework == "" {
		t.Error("compliance framework name must not be empty")
	}
	if !strings.Contains(strings.ToLower(parsed.Compliance.Framework), "pci-dss") {
		t.Errorf("compliance framework = %q, want it to contain 'pci-dss'", parsed.Compliance.Framework)
	}
	if len(parsed.Compliance.Controls) == 0 {
		t.Error("compliance section must include at least one control result")
	}
	// Pass rate must be in [0, 100].
	if parsed.Compliance.PassRate < 0 || parsed.Compliance.PassRate > 100 {
		t.Errorf("compliance pass rate = %.2f, want value in [0, 100]", parsed.Compliance.PassRate)
	}

	// Assert HTML: 'pci' keyword and domain must appear.
	htmlContent := string(htmlBytes)
	if !strings.Contains(strings.ToLower(htmlContent), "pci") {
		t.Error("HTML report does not contain 'pci' compliance reference")
	}
	if !strings.Contains(htmlContent, domain) {
		t.Errorf("HTML report does not contain domain %q", domain)
	}
}

// ---------------------------------------------------------------------------
// TestE2E_ScanCommand_GradeCalculation
// ---------------------------------------------------------------------------

// TestE2E_ScanCommand_GradeCalculation verifies that the grade produced in
// JSON and HTML reports is correct for each documented severity profile.
func TestE2E_ScanCommand_GradeCalculation(t *testing.T) {
	tests := []struct {
		name          string
		specs         []findingSpec
		expectedGrade string
	}{
		{
			name:          "grade A — no vulnerabilities",
			specs:         nil,
			expectedGrade: "A",
		},
		{
			name:          "grade B — 1-3 high, no critical",
			specs:         []findingSpec{{title: "XSS", severity: finding.SeverityHigh}, {title: "SQLi", severity: finding.SeverityHigh}},
			expectedGrade: "B",
		},
		{
			name:          "grade C — exactly 1 critical",
			specs:         []findingSpec{{title: "RCE", severity: finding.SeverityCritical}},
			expectedGrade: "C",
		},
		{
			name: "grade D — 2-5 critical",
			specs: []findingSpec{
				{title: "RCE 1", severity: finding.SeverityCritical},
				{title: "RCE 2", severity: finding.SeverityCritical},
				{title: "RCE 3", severity: finding.SeverityCritical},
			},
			expectedGrade: "D",
		},
		{
			name: "grade F — 6+ critical",
			specs: []findingSpec{
				{title: "RCE 1", severity: finding.SeverityCritical},
				{title: "RCE 2", severity: finding.SeverityCritical},
				{title: "RCE 3", severity: finding.SeverityCritical},
				{title: "RCE 4", severity: finding.SeverityCritical},
				{title: "RCE 5", severity: finding.SeverityCritical},
				{title: "RCE 6", severity: finding.SeverityCritical},
			},
			expectedGrade: "F",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			result := buildMockPipelineResult("grade-test.example.com", tc.specs)

			// Act: derive grade through the summary path.
			summary := report.SummarizeFindings(result.Findings)
			grade := report.CalculateGrade(summary)

			// Assert: standalone grade function.
			if grade != tc.expectedGrade {
				t.Errorf("CalculateGrade = %q, want %q (critical=%d, high=%d)",
					grade, tc.expectedGrade, summary.Critical, summary.High)
			}

			// Assert: grade appears in JSON report.
			jsonBytes, err := report.GenerateJSON(result, nil)
			if err != nil {
				t.Fatalf("GenerateJSON: %v", err)
			}
			var parsed report.JSONReport
			if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
				t.Fatalf("JSON unmarshal: %v", err)
			}
			if parsed.Grade != tc.expectedGrade {
				t.Errorf("JSON report grade = %q, want %q", parsed.Grade, tc.expectedGrade)
			}

			// Assert: grade appears in HTML report.
			htmlBytes, err := report.GenerateHTML(result, nil)
			if err != nil {
				t.Fatalf("GenerateHTML: %v", err)
			}
			if !strings.Contains(string(htmlBytes), tc.expectedGrade) {
				t.Errorf("HTML report does not contain grade %q", tc.expectedGrade)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestE2E_ScanCommand_DefaultFormat
// ---------------------------------------------------------------------------

// TestE2E_ScanCommand_DefaultFormat verifies that the scan command defaults to
// HTML output when neither --format nor a .json output path is specified.
func TestE2E_ScanCommand_DefaultFormat(t *testing.T) {
	t.Skip("requires network and installed tools")
	// Arrange
	outputPath := tempReportPath(t, "report.html")
	root := cmd.RootCmd()

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"scan", "default-format.example.com", "--output", outputPath})
	defer root.SetArgs([]string{})

	// Act: execute the scan command in stub-pipeline mode.
	if err := root.Execute(); err != nil {
		t.Fatalf("scan command returned unexpected error: %v", err)
	}

	// Assert: output file is HTML.
	assertFileExists(t, outputPath)
	assertFileNotEmpty(t, outputPath)
	content := readFileContent(t, outputPath)
	if !strings.Contains(content, "<html") {
		t.Errorf("default format output does not appear to be HTML; starts with: %.200s", content)
	}
}

// ---------------------------------------------------------------------------
// TestE2E_ScanCommand_JSONFormatInferred
// ---------------------------------------------------------------------------

// TestE2E_ScanCommand_JSONFormatInferred verifies that when --format json is
// provided, the scan command writes a valid JSON report to the output file.
// Note: format-from-extension inference requires a fresh cobra command state;
// we use the explicit --format flag here to avoid global-state contamination
// between parallel test runs.
func TestE2E_ScanCommand_JSONFormatInferred(t *testing.T) {
	t.Skip("requires network and installed tools")
	// Arrange
	outputPath := tempReportPath(t, "report.json")
	root := cmd.RootCmd()

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	// Pass --format json explicitly so the test is independent of flag state.
	root.SetArgs([]string{"scan", "infer-json.example.com", "--output", outputPath, "--format", "json"})
	defer root.SetArgs([]string{})

	// Act
	if err := root.Execute(); err != nil {
		t.Fatalf("scan command returned unexpected error: %v", err)
	}

	// Assert: file must be valid JSON with correct domain.
	assertFileExists(t, outputPath)
	assertFileNotEmpty(t, outputPath)

	content := readFileContent(t, outputPath)
	var parsed report.JSONReport
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		t.Fatalf("output file is not valid JSON: %v\ncontent: %.300s", err, content)
	}
	if parsed.Domain != "infer-json.example.com" {
		t.Errorf("JSON domain = %q, want %q", parsed.Domain, "infer-json.example.com")
	}
	if parsed.Grade == "" {
		t.Error("JSON grade must not be empty")
	}
}

// ---------------------------------------------------------------------------
// TestE2E_ScanCommand_InvalidDomain
// ---------------------------------------------------------------------------

// TestE2E_ScanCommand_InvalidDomain verifies that the scan command returns an
// error when no domain argument is provided (cobra ExactArgs(1) validation).
func TestE2E_ScanCommand_InvalidDomain(t *testing.T) {
	// Arrange
	root := cmd.RootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"scan"}) // no domain
	defer root.SetArgs([]string{})

	// Act
	err := root.Execute()

	// Assert
	if err == nil {
		t.Error("expected an error when scan is run without a domain argument, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestE2E_FullPipelineFlow_MockAdapters
// ---------------------------------------------------------------------------

// TestE2E_FullPipelineFlow_MockAdapters runs the complete pipeline with mock
// adapters and verifies that findings flow from raw tool output through
// normalisation to the final report.
func TestE2E_FullPipelineFlow_MockAdapters(t *testing.T) {
	// Arrange: raw findings that the mock nuclei adapter will emit.
	// Nuclei normalizer reads title from info.name and severity from info.severity
	// (nested under the "info" key), matching the real nuclei JSON output format.
	const domain = "e2e-pipeline.example.com"
	mockFindings := []adapter.RawFinding{
		{
			ToolName: "nuclei",
			ToolOutput: map[string]interface{}{
				"host": domain,
				"info": map[string]interface{}{
					"name":     "Remote Code Execution",
					"severity": "critical",
				},
			},
		},
		{
			ToolName: "nuclei",
			ToolOutput: map[string]interface{}{
				"host": domain,
				"info": map[string]interface{}{
					"name":     "Cross-Site Scripting",
					"severity": "high",
				},
			},
		},
	}

	// Act: run the pipeline with mock adapters (subfinder + nuclei).
	pipelineResult := mockPipelineRun(t, domain, mockFindings)

	// Assert pipeline result.
	if pipelineResult.Domain != domain {
		t.Errorf("pipeline domain = %q, want %q", pipelineResult.Domain, domain)
	}
	if len(pipelineResult.Findings) != 2 {
		t.Fatalf("expected 2 pipeline findings, got %d", len(pipelineResult.Findings))
	}

	// Generate JSON report from the pipeline result.
	jsonBytes, err := report.GenerateJSON(pipelineResult, nil)
	if err != nil {
		t.Fatalf("GenerateJSON: %v", err)
	}
	var parsed report.JSONReport
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	// Domain propagation.
	if parsed.Domain != domain {
		t.Errorf("JSON domain = %q, want %q", parsed.Domain, domain)
	}

	// 1 critical + 1 high → grade C (1 critical takes precedence).
	if parsed.Grade != "C" {
		t.Errorf("grade = %q, want C (1 critical finding)", parsed.Grade)
	}

	// Summary counts.
	if parsed.Summary.Critical != 1 {
		t.Errorf("summary.critical = %d, want 1", parsed.Summary.Critical)
	}
	if parsed.Summary.High != 1 {
		t.Errorf("summary.high = %d, want 1", parsed.Summary.High)
	}
	if parsed.Summary.Total != 2 {
		t.Errorf("summary.total = %d, want 2", parsed.Summary.Total)
	}

	// All finding titles must appear in the JSON findings list.
	titlesInReport := make(map[string]bool)
	for _, f := range parsed.Findings {
		titlesInReport[f.Title] = true
	}
	for _, wantTitle := range []string{"Remote Code Execution", "Cross-Site Scripting"} {
		if !titlesInReport[wantTitle] {
			t.Errorf("finding %q missing from JSON report; got: %v", wantTitle, titlesInReport)
		}
	}

	// Generate HTML report and verify domain + grade appear.
	htmlBytes, err := report.GenerateHTML(pipelineResult, nil)
	if err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	htmlContent := string(htmlBytes)
	if !strings.Contains(htmlContent, domain) {
		t.Errorf("HTML report does not contain domain %q", domain)
	}
	// Grade C should appear in the HTML output.
	if !strings.Contains(htmlContent, "C") {
		t.Error("HTML report does not contain grade C")
	}
}

// ---------------------------------------------------------------------------
// TestE2E_OutputFileWritten
// ---------------------------------------------------------------------------

// TestE2E_OutputFileWritten verifies that the scan command writes the report
// to the specified --output path with the correct format.
//
// Note: scan.go writes progress messages directly to os.Stdout (not to the
// cobra command's configured output writer), so this test verifies file
// content only — not stdout capture — to avoid coupling to internal I/O
// wiring that may change in sprint-2.
func TestE2E_OutputFileWritten(t *testing.T) {
	t.Skip("requires network and installed tools")
	// Arrange
	outputPath := tempReportPath(t, "scan-output.html")
	root := cmd.RootCmd()

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"scan", "output-test.example.com", "--output", outputPath, "--format", "html"})
	defer root.SetArgs([]string{})

	// Act
	if err := root.Execute(); err != nil {
		t.Fatalf("scan command returned unexpected error: %v", err)
	}

	// Assert: report file exists, is non-empty HTML.
	assertFileExists(t, outputPath)
	assertFileNotEmpty(t, outputPath)
	content := readFileContent(t, outputPath)
	if !strings.Contains(content, "<html") {
		t.Errorf("output file does not appear to be HTML; starts: %.200s", content)
	}
	// Domain must be present in the output file.
	if !strings.Contains(content, "output-test.example.com") {
		t.Errorf("HTML report does not contain the scanned domain %q", "output-test.example.com")
	}
}

// ---------------------------------------------------------------------------
// TestE2E_BothFormats
// ---------------------------------------------------------------------------

// TestE2E_BothFormats verifies that --format both produces valid HTML and JSON
// output files with the correct content at the expected paths.
func TestE2E_BothFormats(t *testing.T) {
	t.Skip("requires network and installed tools")
	// Arrange
	dir := createTempOutputDir(t)
	basePath := dir + "/both-format-report"
	root := cmd.RootCmd()

	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"scan", "both.example.com", "--output", basePath, "--format", "both"})
	defer root.SetArgs([]string{})

	// Act
	if err := root.Execute(); err != nil {
		t.Fatalf("scan --format both returned error: %v", err)
	}

	// Assert: both files exist and contain correct content.
	htmlPath := basePath + ".html"
	jsonPath := basePath + ".json"

	assertFileExists(t, htmlPath)
	assertFileNotEmpty(t, htmlPath)
	assertFileExists(t, jsonPath)
	assertFileNotEmpty(t, jsonPath)

	// JSON must parse correctly.
	jsonContent := readFileContent(t, jsonPath)
	var parsed report.JSONReport
	if err := json.Unmarshal([]byte(jsonContent), &parsed); err != nil {
		t.Fatalf("--format both JSON is not valid JSON: %v", err)
	}

	// HTML must contain the <html> tag.
	htmlContent := readFileContent(t, htmlPath)
	if !strings.Contains(htmlContent, "<html") {
		t.Error("--format both HTML file does not contain <html> tag")
	}
}
