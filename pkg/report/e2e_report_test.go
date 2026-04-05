// E2E tests for report generation — Story 3.6
package report_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/finding"
	"github.com/scryve/scryve/pkg/pipeline"
	"github.com/scryve/scryve/pkg/report"
)

// --------------------------------------------------------------------------
// Security Grade tests
// --------------------------------------------------------------------------

func TestE2E_Grade_A(t *testing.T) {
	s := finding.ResultSummary{Critical: 0, High: 0, Medium: 5, Low: 10, Info: 20}
	if g := report.CalculateGrade(s); g != "A" {
		t.Errorf("0 crit 0 high → %q, want A", g)
	}
}

func TestE2E_Grade_B_2High(t *testing.T) {
	s := finding.ResultSummary{Critical: 0, High: 2}
	if g := report.CalculateGrade(s); g != "B" {
		t.Errorf("0 crit 2 high → %q, want B", g)
	}
}

func TestE2E_Grade_B_3High(t *testing.T) {
	s := finding.ResultSummary{Critical: 0, High: 3}
	if g := report.CalculateGrade(s); g != "B" {
		t.Errorf("0 crit 3 high → %q, want B", g)
	}
}

func TestE2E_Grade_C_4High(t *testing.T) {
	s := finding.ResultSummary{Critical: 0, High: 4}
	if g := report.CalculateGrade(s); g != "C" {
		t.Errorf("0 crit 4 high → %q, want C", g)
	}
}

func TestE2E_Grade_C_1Critical(t *testing.T) {
	s := finding.ResultSummary{Critical: 1, High: 0}
	if g := report.CalculateGrade(s); g != "C" {
		t.Errorf("1 crit → %q, want C", g)
	}
}

func TestE2E_Grade_D(t *testing.T) {
	s := finding.ResultSummary{Critical: 3}
	if g := report.CalculateGrade(s); g != "D" {
		t.Errorf("3 crit → %q, want D", g)
	}
}

func TestE2E_Grade_F(t *testing.T) {
	s := finding.ResultSummary{Critical: 7}
	if g := report.CalculateGrade(s); g != "F" {
		t.Errorf("7 crit → %q, want F", g)
	}
}

// --------------------------------------------------------------------------
// SummarizeFindings
// --------------------------------------------------------------------------

func TestE2E_SummarizeFindings(t *testing.T) {
	findings := []finding.Finding{
		{Severity: finding.SeverityCritical},
		{Severity: finding.SeverityHigh},
		{Severity: finding.SeverityHigh},
		{Severity: finding.SeverityMedium},
		{Severity: finding.SeverityLow},
		{Severity: finding.SeverityInfo},
	}
	s := report.SummarizeFindings(findings)
	if s.Critical != 1 || s.High != 2 || s.Medium != 1 || s.Low != 1 || s.Info != 1 {
		t.Errorf("summary = %+v, want 1/2/1/1/1", s)
	}
}

// --------------------------------------------------------------------------
// HTML report
// --------------------------------------------------------------------------

func makeResult(findings []finding.Finding) *pipeline.PipelineResult {
	return &pipeline.PipelineResult{
		Domain:      "example.com",
		Findings:    findings,
		StartedAt:   time.Now().Add(-time.Minute),
		CompletedAt: time.Now(),
	}
}

func TestE2E_HTMLReport_Valid(t *testing.T) {
	result := makeResult([]finding.Finding{
		{Title: "Test Vuln", Severity: finding.SeverityHigh, Host: "example.com"},
	})
	html, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(html) == 0 {
		t.Fatal("HTML report should not be empty")
	}
	if !strings.Contains(string(html), "<html") {
		t.Error("HTML report should contain <html tag")
	}
	if !strings.Contains(string(html), "example.com") {
		t.Error("HTML report should contain the domain")
	}
}

func TestE2E_HTMLReport_XSSSafety(t *testing.T) {
	// FIXED: Switched from text/template to html/template in html.go.
	// html/template auto-escapes all interpolated values.
	result := makeResult([]finding.Finding{
		{Title: "<script>alert(1)</script>", Severity: finding.SeverityHigh, Host: "example.com"},
	})
	html, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	content := string(html)
	if strings.Contains(content, "<script>alert(1)</script>") {
		t.Error("HTML report contains unescaped <script> tag — XSS vulnerability!")
	}
}

func TestE2E_HTMLReport_EmptyFindings(t *testing.T) {
	result := makeResult(nil)
	html, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(html) == 0 {
		t.Fatal("HTML report for empty findings should still produce output")
	}
}

// --------------------------------------------------------------------------
// JSON report
// --------------------------------------------------------------------------

func TestE2E_JSONReport_Valid(t *testing.T) {
	result := makeResult([]finding.Finding{
		{Title: "Test Vuln", Severity: finding.SeverityHigh, Host: "example.com"},
	})
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("JSON report should not be empty")
	}
	// Should be valid JSON
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v", err)
	}
}

func TestE2E_JSONReport_Schema(t *testing.T) {
	result := makeResult([]finding.Finding{
		{Title: "Vuln", Severity: finding.SeverityHigh},
	})
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	json.Unmarshal(data, &parsed)

	// Check required fields
	required := []string{"domain", "grade", "summary", "findings"}
	for _, key := range required {
		if _, ok := parsed[key]; !ok {
			t.Errorf("JSON report missing required field %q", key)
		}
	}
}

func TestE2E_JSONReport_EmptyFindings(t *testing.T) {
	// FIXED: Added nil→empty slice guard in GenerateJSON before marshaling.
	result := makeResult(nil)
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	findings, ok := parsed["findings"]
	if !ok {
		t.Fatal("JSON report missing 'findings' field")
	}
	arr, ok := findings.([]any)
	if !ok {
		t.Fatal("findings should be an array, got null")
	}
	if len(arr) != 0 {
		t.Errorf("empty findings should produce empty array, got %d items", len(arr))
	}
}
