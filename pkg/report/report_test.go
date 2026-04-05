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

// ---------------------------------------------------------------------------
// CalculateGrade tests
// ---------------------------------------------------------------------------

func TestCalculateGrade_AWithNoFindings(t *testing.T) {
	s := finding.ResultSummary{}
	if g := report.CalculateGrade(s); g != "A" {
		t.Errorf("expected A for zero findings, got %s", g)
	}
}

func TestCalculateGrade_AWithOnlyLowAndInfo(t *testing.T) {
	s := finding.ResultSummary{Total: 5, Low: 3, Info: 2}
	if g := report.CalculateGrade(s); g != "A" {
		t.Errorf("expected A for low/info only, got %s", g)
	}
}

func TestCalculateGrade_AWithOnlyMedium(t *testing.T) {
	s := finding.ResultSummary{Total: 3, Medium: 3}
	if g := report.CalculateGrade(s); g != "A" {
		t.Errorf("expected A for medium only (no critical/high), got %s", g)
	}
}

func TestCalculateGrade_BWith1High(t *testing.T) {
	s := finding.ResultSummary{Total: 1, High: 1}
	if g := report.CalculateGrade(s); g != "B" {
		t.Errorf("expected B for 1 high, got %s", g)
	}
}

func TestCalculateGrade_BWith3High(t *testing.T) {
	s := finding.ResultSummary{Total: 3, High: 3}
	if g := report.CalculateGrade(s); g != "B" {
		t.Errorf("expected B for 3 high, got %s", g)
	}
}

func TestCalculateGrade_CWith4High(t *testing.T) {
	s := finding.ResultSummary{Total: 4, High: 4}
	if g := report.CalculateGrade(s); g != "C" {
		t.Errorf("expected C for 4+ high, got %s", g)
	}
}

func TestCalculateGrade_CWith1Critical(t *testing.T) {
	s := finding.ResultSummary{Total: 1, Critical: 1}
	if g := report.CalculateGrade(s); g != "C" {
		t.Errorf("expected C for 1 critical, got %s", g)
	}
}

func TestCalculateGrade_DWith2Critical(t *testing.T) {
	s := finding.ResultSummary{Total: 2, Critical: 2}
	if g := report.CalculateGrade(s); g != "D" {
		t.Errorf("expected D for 2 critical, got %s", g)
	}
}

func TestCalculateGrade_DWith5Critical(t *testing.T) {
	s := finding.ResultSummary{Total: 5, Critical: 5}
	if g := report.CalculateGrade(s); g != "D" {
		t.Errorf("expected D for 5 critical, got %s", g)
	}
}

func TestCalculateGrade_FWith6Critical(t *testing.T) {
	s := finding.ResultSummary{Total: 6, Critical: 6}
	if g := report.CalculateGrade(s); g != "F" {
		t.Errorf("expected F for 6+ critical, got %s", g)
	}
}

func TestCalculateGrade_FWith10Critical(t *testing.T) {
	s := finding.ResultSummary{Total: 10, Critical: 10}
	if g := report.CalculateGrade(s); g != "F" {
		t.Errorf("expected F for 10 critical, got %s", g)
	}
}

// ---------------------------------------------------------------------------
// GradeColor tests
// ---------------------------------------------------------------------------

func TestGradeColor(t *testing.T) {
	tests := []struct {
		grade string
		want  string
	}{
		{"A", "#27ae60"},
		{"B", "#2980b9"},
		{"C", "#f39c12"},
		{"D", "#e67e22"},
		{"F", "#c0392b"},
		{"X", "#7f8c8d"}, // unknown → fallback gray
	}
	for _, tc := range tests {
		got := report.GradeColor(tc.grade)
		if got != tc.want {
			t.Errorf("GradeColor(%q) = %q, want %q", tc.grade, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// buildMinimalResult returns a PipelineResult for testing.
func buildMinimalResult() *pipeline.PipelineResult {
	now := time.Now()
	return &pipeline.PipelineResult{
		Domain:      "example.com",
		StartedAt:   now.Add(-30 * time.Second),
		CompletedAt: now,
		Findings: []finding.Finding{
			{
				ID:          "f1",
				Title:       "SQL Injection",
				Description: "SQL injection found",
				Severity:    finding.SeverityCritical,
				CVSS:        9.8,
				CWE:         "CWE-89",
				CVE:         "CVE-2021-1234",
				Host:        "api.example.com",
				Tool:        "nuclei",
				Evidence: finding.Evidence{
					Proof: "' OR 1=1 --",
					URL:   "https://api.example.com/login",
				},
				Tags: []string{"injection", "sqli"},
			},
			{
				ID:       "f2",
				Title:    "Missing SPF Record",
				Severity: finding.SeverityMedium,
				Host:     "example.com",
				Tool:     "dns",
				Tags:     []string{"spf", "email"},
			},
		},
		Stages: []pipeline.StageResult{
			{
				Stage:    pipeline.Stage{Name: "subfinder"},
				Status:   "completed",
				Duration: 5 * time.Second,
				Stats:    map[string]int{"subdomains": 12},
			},
			{
				Stage:    pipeline.Stage{Name: "nuclei"},
				Status:   "completed",
				Duration: 20 * time.Second,
				Stats:    map[string]int{"findings": 2},
			},
		},
	}
}

// mockComplianceMapper satisfies report.ComplianceReporter.
type mockComplianceMapper struct{}

func (m *mockComplianceMapper) Framework() string { return "test-framework-1.0" }
func (m *mockComplianceMapper) Version() string   { return "1.0" }
func (m *mockComplianceMapper) MapFinding(f *finding.Finding) []finding.ComplianceMapping {
	return []finding.ComplianceMapping{{Framework: "test-framework-1.0", ControlID: "C-1", Status: "fail"}}
}
func (m *mockComplianceMapper) MapFindings(findings []finding.Finding) []finding.Finding {
	for i := range findings {
		mappings := m.MapFinding(&findings[i])
		findings[i].Compliance = append(findings[i].Compliance, mappings...)
	}
	return findings
}
func (m *mockComplianceMapper) Controls() []report.Control {
	return []report.Control{
		{ID: "C-1", Title: "Test Control", Description: "A test control", CWEs: []string{"CWE-89"}},
		{ID: "C-2", Title: "Another Control", Description: "Another control", CWEs: nil},
	}
}

// ---------------------------------------------------------------------------
// GenerateJSON tests
// ---------------------------------------------------------------------------

func TestGenerateJSON_ValidJSON(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatalf("GenerateJSON returned error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestGenerateJSON_ContainsDomain(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}
	if !strings.Contains(string(data), "example.com") {
		t.Error("JSON output does not contain domain")
	}
}

func TestGenerateJSON_ContainsGrade(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}
	// result has 1 critical → grade C
	if !strings.Contains(string(data), `"grade"`) {
		t.Error("JSON output does not contain grade field")
	}
}

func TestGenerateJSON_ContainsFindings(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}
	if !strings.Contains(string(data), "SQL Injection") {
		t.Error("JSON output does not contain finding title")
	}
}

func TestGenerateJSON_ContainsSummary(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}
	if !strings.Contains(string(data), `"summary"`) {
		t.Error("JSON output does not contain summary field")
	}
}

func TestGenerateJSON_ContainsStages(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}
	if !strings.Contains(string(data), `"stages"`) {
		t.Error("JSON output does not contain stages field")
	}
}

func TestGenerateJSON_ComplianceSectionPresentWhenMapper(t *testing.T) {
	result := buildMinimalResult()
	mapper := &mockComplianceMapper{}
	data, err := report.GenerateJSON(result, mapper)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}
	if !strings.Contains(string(data), `"compliance"`) {
		t.Error("JSON output does not contain compliance field when mapper is provided")
	}
}

func TestGenerateJSON_ComplianceSectionAbsentWithoutMapper(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}
	var out report.JSONReport
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Compliance != nil {
		t.Error("compliance field should be nil when no mapper is provided")
	}
}

func TestGenerateJSON_NilResultReturnsError(t *testing.T) {
	_, err := report.GenerateJSON(nil, nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestGenerateJSON_SummaryCountsCorrect(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateJSON(result, nil)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}
	var out report.JSONReport
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Summary.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", out.Summary.Critical)
	}
	if out.Summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", out.Summary.Medium)
	}
}

// ---------------------------------------------------------------------------
// GenerateHTML tests
// ---------------------------------------------------------------------------

func TestGenerateHTML_ValidHTML(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML returned error: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "<!DOCTYPE html>") && !strings.Contains(html, "<html") {
		t.Error("output does not look like valid HTML")
	}
}

func TestGenerateHTML_ContainsDomain(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	if !strings.Contains(string(data), "example.com") {
		t.Error("HTML output does not contain domain name")
	}
}

func TestGenerateHTML_ContainsGradeBadge(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "grade") {
		t.Error("HTML output does not contain grade section")
	}
}

func TestGenerateHTML_ContainsSummaryCards(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	html := string(data)
	// Verify the four severity labels appear
	for _, label := range []string{"Critical", "High", "Medium", "Low"} {
		if !strings.Contains(html, label) {
			t.Errorf("HTML output does not contain severity label %q", label)
		}
	}
}

func TestGenerateHTML_ContainsFindingsTable(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	if !strings.Contains(string(data), "SQL Injection") {
		t.Error("HTML output does not contain finding title")
	}
}

func TestGenerateHTML_ContainsEmbeddedCSS(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	html := string(data)
	if !strings.Contains(html, "<style>") {
		t.Error("HTML output does not contain embedded <style> tag")
	}
}

func TestGenerateHTML_ContainsFooter(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	if !strings.Contains(string(data), "Scryve") {
		t.Error("HTML footer does not reference Scryve")
	}
}

func TestGenerateHTML_ComplianceSectionAbsentWithoutMapper(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	// Without a compliance mapper there should be no compliance section heading
	if strings.Contains(string(data), "Compliance Framework") {
		t.Error("HTML should not contain compliance section when mapper is nil")
	}
}

func TestGenerateHTML_ComplianceSectionPresentWithMapper(t *testing.T) {
	result := buildMinimalResult()
	mapper := &mockComplianceMapper{}
	data, err := report.GenerateHTML(result, mapper)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	if !strings.Contains(string(data), "Compliance") {
		t.Error("HTML should contain compliance section when mapper is provided")
	}
}

func TestGenerateHTML_NilResultReturnsError(t *testing.T) {
	_, err := report.GenerateHTML(nil, nil)
	if err == nil {
		t.Error("expected error for nil result")
	}
}

func TestGenerateHTML_ContainsEmailSecuritySection(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	// The SPF finding exists in test data → email security section should appear
	if !strings.Contains(string(data), "SPF") && !strings.Contains(string(data), "Email Security") {
		t.Error("HTML should contain email security section or SPF reference")
	}
}

func TestGenerateHTML_ContainsStagesSummary(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	if !strings.Contains(string(data), "subfinder") {
		t.Error("HTML should contain stage names")
	}
}

func TestGenerateHTML_PrintStyles(t *testing.T) {
	result := buildMinimalResult()
	data, err := report.GenerateHTML(result, nil)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	if !strings.Contains(string(data), "@media print") {
		t.Error("HTML should contain @media print styles")
	}
}

// ---------------------------------------------------------------------------
// ReportConfig tests
// ---------------------------------------------------------------------------

func TestReportConfig_Defaults(t *testing.T) {
	cfg := report.ReportConfig{}
	if cfg.Format != "" {
		t.Error("default format should be empty string")
	}
	if cfg.Framework != "" {
		t.Error("default framework should be empty string")
	}
}
