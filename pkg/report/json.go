package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/scryve/scryve/pkg/finding"
	"github.com/scryve/scryve/pkg/pipeline"
)

// JSONReport is the top-level structure written to a .json report file.
type JSONReport struct {
	// Domain is the root domain that was scanned.
	Domain string `json:"domain"`

	// ScanDate is the UTC timestamp when the scan started.
	ScanDate time.Time `json:"scan_date"`

	// Duration is the total wall-clock time of the scan in nanoseconds.
	// Clients should format this value for display.
	Duration time.Duration `json:"duration"`

	// Summary contains per-severity finding counts.
	Summary finding.ResultSummary `json:"summary"`

	// Grade is the letter grade (A–F) derived from the summary.
	Grade string `json:"grade"`

	// Findings is the full list of normalised findings.
	Findings []finding.Finding `json:"findings"`

	// Compliance contains the compliance mapping report, populated only when a
	// mapper is provided to GenerateJSON.
	Compliance *ComplianceReport `json:"compliance,omitempty"`

	// Stages is the per-stage execution summary.
	Stages []StageReport `json:"stages"`

	// EmailSecurity is populated when any email-security findings are present.
	EmailSecurity *EmailReport `json:"email_security,omitempty"`
}

// ComplianceReport summarizes compliance coverage for a given framework.
type ComplianceReport struct {
	// Framework is the canonical framework identifier (e.g. "pci-dss-4.0").
	Framework string `json:"framework"`

	// Controls holds one ControlResult per control in the framework.
	Controls []ControlResult `json:"controls"`

	// PassRate is the fraction of controls that have no failing findings,
	// expressed as a percentage (0–100).
	PassRate float64 `json:"pass_rate"`
}

// ControlResult captures the compliance status of a single framework control.
type ControlResult struct {
	// ID is the control identifier (e.g. "6.2.4").
	ID string `json:"id"`

	// Title is the short human-readable name of the control.
	Title string `json:"title"`

	// Status is one of "pass", "fail", or "not_tested".
	Status string `json:"status"`

	// FindingsCount is the number of findings that violate this control.
	FindingsCount int `json:"findings_count"`
}

// StageReport captures the execution summary of one pipeline stage.
type StageReport struct {
	// Name is the stage identifier (e.g. "subfinder").
	Name string `json:"name"`

	// Status is one of "completed", "failed", or "skipped".
	Status string `json:"status"`

	// DurationMs is the wall-clock time in milliseconds.
	DurationMs int64 `json:"duration_ms"`

	// Stats holds optional counters emitted by the stage.
	Stats map[string]int `json:"stats,omitempty"`
}

// EmailReport captures the summary of email-security findings.
type EmailReport struct {
	// SPF is the SPF check status: "pass", "fail", or "not_tested".
	SPF string `json:"spf"`

	// DKIM is the DKIM check status.
	DKIM string `json:"dkim"`

	// DMARC is the DMARC check status.
	DMARC string `json:"dmarc"`

	// Findings lists the email-security related findings.
	Findings []finding.Finding `json:"findings,omitempty"`
}

// GenerateJSON builds a JSONReport from the pipeline result and optional
// compliance mapper, then marshals it to indented JSON bytes.
//
// Returns an error if result is nil or marshaling fails.
func GenerateJSON(result *pipeline.PipelineResult, mapper ComplianceReporter) ([]byte, error) {
	if result == nil {
		return nil, fmt.Errorf("report: pipeline result must not be nil")
	}

	// Enrich findings with compliance mappings when a mapper is provided.
	findings := result.Findings
	if mapper != nil {
		findings = mapper.MapFindings(findings)
	}

	summary := buildSummary(findings)
	grade := CalculateGrade(summary)

	// Ensure findings is never nil so JSON serializes as [] not null.
	if findings == nil {
		findings = []finding.Finding{}
	}

	report := JSONReport{
		Domain:   result.Domain,
		ScanDate: result.StartedAt.UTC(),
		Duration: result.CompletedAt.Sub(result.StartedAt),
		Summary:  summary,
		Grade:    grade,
		Findings: findings,
		Stages:   buildStageReports(result.Stages),
	}

	// Build compliance section.
	if mapper != nil {
		report.Compliance = buildComplianceReport(mapper, findings)
	}

	// Build email security section.
	report.EmailSecurity = buildEmailReport(findings)

	return json.MarshalIndent(report, "", "  ")
}

// buildStageReports converts pipeline.StageResult values to StageReport.
func buildStageReports(stages []pipeline.StageResult) []StageReport {
	out := make([]StageReport, len(stages))
	for i, s := range stages {
		out[i] = StageReport{
			Name:       s.Stage.Name,
			Status:     s.Status,
			DurationMs: s.Duration.Milliseconds(),
			Stats:      s.Stats,
		}
	}
	return out
}

// buildComplianceReport computes per-control pass/fail status and the overall
// pass rate for the given set of enriched findings.
func buildComplianceReport(mapper ComplianceReporter, findings []finding.Finding) *ComplianceReport {
	controls := mapper.Controls()
	if len(controls) == 0 {
		return &ComplianceReport{
			Framework: mapper.Framework(),
			PassRate:  100.0,
		}
	}

	// Build a map from controlID → count of failing findings.
	failCounts := make(map[string]int)
	for _, f := range findings {
		for _, cm := range f.Compliance {
			if cm.Framework == mapper.Framework() && cm.Status == "fail" {
				failCounts[cm.ControlID]++
			}
		}
	}

	results := make([]ControlResult, len(controls))
	passed := 0
	for i, c := range controls {
		count := failCounts[c.ID]
		var status string
		switch {
		case count > 0:
			status = "fail"
		default:
			status = "pass"
			passed++
		}
		results[i] = ControlResult{
			ID:            c.ID,
			Title:         c.Title,
			Status:        status,
			FindingsCount: count,
		}
	}

	passRate := float64(passed) / float64(len(controls)) * 100.0

	return &ComplianceReport{
		Framework: mapper.Framework(),
		Controls:  results,
		PassRate:  passRate,
	}
}

// buildEmailReport extracts email-security findings and determines the status
// of each email-security mechanism (SPF, DKIM, DMARC).
func buildEmailReport(findings []finding.Finding) *EmailReport {
	var emailFindings []finding.Finding
	for _, f := range findings {
		if isEmailFinding(f) {
			emailFindings = append(emailFindings, f)
		}
	}
	if len(emailFindings) == 0 {
		return nil
	}

	// Default to "not_tested"; upgrade to "fail" if a matching finding exists.
	spf, dkim, dmarc := "not_tested", "not_tested", "not_tested"
	for _, f := range emailFindings {
		title := f.Title
		switch {
		case containsKeyword(title, f.Tags, "spf"):
			if spf != "fail" {
				spf = severityToStatus(f.Severity)
			}
		case containsKeyword(title, f.Tags, "dkim"):
			if dkim != "fail" {
				dkim = severityToStatus(f.Severity)
			}
		case containsKeyword(title, f.Tags, "dmarc"):
			if dmarc != "fail" {
				dmarc = severityToStatus(f.Severity)
			}
		}
	}

	return &EmailReport{
		SPF:      spf,
		DKIM:     dkim,
		DMARC:    dmarc,
		Findings: emailFindings,
	}
}

// containsKeyword checks whether the title or any tag contains kw (case-insensitive).
func containsKeyword(title string, tags []string, kw string) bool {
	if containsCI(title, kw) {
		return true
	}
	for _, t := range tags {
		if containsCI(t, kw) {
			return true
		}
	}
	return false
}

// severityToStatus maps a finding severity to a simple "pass"/"fail" status
// for the email section. Any non-info severity is treated as a failure.
func severityToStatus(s finding.Severity) string {
	if s == finding.SeverityInfo {
		return "pass"
	}
	return "fail"
}
