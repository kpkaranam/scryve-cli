// Package report provides report generation functionality for Scryve scan
// results. It produces both structured JSON and single-file HTML reports from
// a pipeline.PipelineResult, with optional compliance mapping annotation.
package report

import (
	"strings"

	"github.com/scryve/scryve/pkg/finding"
)

// ReportConfig carries the user-supplied options that control what gets
// generated and where it is written.
type ReportConfig struct {
	// OutputPath is the destination file path for the report.
	// An empty string means write to stdout (JSON) or skip file output.
	OutputPath string

	// Format selects the output format: "html", "json", or "both".
	// An empty string defaults to "html".
	Format string

	// Framework is the compliance framework name (e.g. "pci-dss-4.0").
	// An empty string means skip compliance mapping.
	Framework string
}

// Control is a local alias type used by report consumers that need control
// data from a compliance mapper without depending directly on the compliance
// package. It mirrors compliance.Control exactly.
type Control struct {
	// ID is the control identifier within the framework.
	ID string

	// Title is the short human-readable name of the control.
	Title string

	// Description provides additional context.
	Description string

	// CWEs lists the CWE identifiers that indicate a violation of this control.
	CWEs []string
}

// ComplianceReporter is the subset of compliance.ComplianceMapper that the
// report package needs. Using a local interface avoids a circular dependency.
type ComplianceReporter interface {
	// Framework returns the canonical framework identifier.
	Framework() string

	// Version returns the framework version string.
	Version() string

	// MapFindings enriches findings with compliance mappings and returns them.
	MapFindings(findings []finding.Finding) []finding.Finding

	// Controls returns the full list of controls for pass-rate computation.
	Controls() []Control
}

// CalculateGrade assigns a letter grade (A–F) based on the count of critical
// and high findings in the result summary.
//
// Grading rules:
//   - A: 0 critical, 0 high
//   - B: 0 critical, 1–3 high
//   - C: 0 critical, 4+ high  OR  exactly 1 critical
//   - D: 2–5 critical
//   - F: 6+ critical
func CalculateGrade(s finding.ResultSummary) string {
	switch {
	case s.Critical >= 6:
		return "F"
	case s.Critical >= 2:
		return "D"
	case s.Critical == 1:
		return "C"
	case s.High >= 4:
		return "C"
	case s.High >= 1:
		return "B"
	default:
		return "A"
	}
}

// GradeColor maps a letter grade to a CSS hex color string suitable for use
// in the HTML report. Unknown grades return a neutral gray.
func GradeColor(grade string) string {
	switch grade {
	case "A":
		return "#27ae60" // green
	case "B":
		return "#2980b9" // blue
	case "C":
		return "#f39c12" // yellow-orange
	case "D":
		return "#e67e22" // orange
	case "F":
		return "#c0392b" // red
	default:
		return "#7f8c8d" // gray fallback
	}
}

// SummarizeFindings counts findings by severity from a slice and returns a
// ResultSummary. It is exported so callers (e.g. the CLI) can display a quick
// summary without generating a full report.
func SummarizeFindings(findings []finding.Finding) finding.ResultSummary {
	return buildSummary(findings)
}

// buildSummary is the internal implementation used by the report generators.
func buildSummary(findings []finding.Finding) finding.ResultSummary {
	s := finding.ResultSummary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case finding.SeverityCritical:
			s.Critical++
		case finding.SeverityHigh:
			s.High++
		case finding.SeverityMedium:
			s.Medium++
		case finding.SeverityLow:
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

// containsCI reports whether s contains substr (case-insensitive).
func containsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// isEmailFinding returns true when a finding relates to email security
// (SPF, DKIM, DMARC) based on title or tags — mirrors the logic in the
// compliance package without creating a cross-package dependency.
func isEmailFinding(f finding.Finding) bool {
	keywords := []string{"spf", "dkim", "dmarc", "email"}
	for _, kw := range keywords {
		if strings.Contains(strings.ToLower(f.Title), kw) {
			return true
		}
	}
	for _, tag := range f.Tags {
		for _, kw := range keywords {
			if strings.Contains(strings.ToLower(tag), kw) {
				return true
			}
		}
	}
	return false
}
