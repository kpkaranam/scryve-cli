package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"html/template"
	"time"

	"github.com/scryve/scryve/pkg/finding"
	"github.com/scryve/scryve/pkg/pipeline"
)

//go:embed templates/report.html.tmpl
var reportHTMLTemplate string

// htmlStageReport is a stage report augmented with a formatted duration string
// for template rendering.
type htmlStageReport struct {
	Name              string
	Status            string
	DurationFormatted string
	Stats             map[string]int
}

// htmlData is the root data object passed to the HTML template.
type htmlData struct {
	// Domain is the scanned domain.
	Domain string

	// ScanDateFormatted is the human-readable UTC scan date.
	ScanDateFormatted string

	// DurationFormatted is the human-readable total scan duration.
	DurationFormatted string

	// Grade is the letter grade (A–F).
	Grade string

	// GradeColor is the CSS hex color for the grade badge.
	GradeColor string

	// Summary contains per-severity finding counts.
	Summary finding.ResultSummary

	// Findings is the full list of findings to render.
	Findings []finding.Finding

	VulnFindings      []finding.Finding
	ServiceFindings   []finding.Finding
	SubdomainFindings []finding.Finding
	OtherFindings     []finding.Finding

	// Compliance is populated when a mapper is provided; nil otherwise.
	Compliance *ComplianceReport

	// EmailSecurity is populated when email-security findings are found.
	EmailSecurity *EmailReport

	// Stages is the per-stage summary.
	Stages []htmlStageReport
}

// templateFuncs provides helper functions for use inside the Go template.
var templateFuncs = template.FuncMap{
	// severityWeight returns the numeric weight of a Severity for sort data attrs.
	"severityWeight": func(s finding.Severity) int {
		return finding.SeverityWeight(s)
	},
	// cweid extracts the numeric part of a CWE identifier (e.g. "CWE-89" → "89").
	"cweid": func(cwe string) string {
		upper := strings.ToUpper(strings.TrimSpace(cwe))
		if strings.HasPrefix(upper, "CWE-") {
			return upper[4:]
		}
		return cwe
	},
}

// GenerateHTML renders the embedded HTML template with data derived from
// the pipeline result and optional compliance mapper.
//
// The returned bytes form a complete, single-file HTML document with all CSS
// and JavaScript embedded inline — no external resources required.
//
// Returns an error if result is nil or template rendering fails.
func GenerateHTML(result *pipeline.PipelineResult, mapper ComplianceReporter) ([]byte, error) {
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

	data := htmlData{
		Domain:            result.Domain,
		ScanDateFormatted: result.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		DurationFormatted: formatDuration(result.CompletedAt.Sub(result.StartedAt)),
		Grade:             grade,
		GradeColor:        GradeColor(grade),
		Summary:           summary,
		Findings:          findings,
		Stages:            buildHTMLStageReports(result.Stages),
	}

	if mapper != nil {
		data.Compliance = buildComplianceReport(mapper, findings)
	}

	data.EmailSecurity = buildEmailReport(findings)

	for _, f := range findings {
		switch {
		case f.Severity != finding.SeverityInfo:
			data.VulnFindings = append(data.VulnFindings, f)
		case f.Tool == "httpx":
			data.ServiceFindings = append(data.ServiceFindings, f)
		case f.Tool == "subfinder":
			data.SubdomainFindings = append(data.SubdomainFindings, f)
		default:
			data.OtherFindings = append(data.OtherFindings, f)
		}
	}

	tmpl, err := template.New("report").Funcs(templateFuncs).Parse(reportHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("report: failed to parse HTML template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("report: failed to render HTML template: %w", err)
	}

	return buf.Bytes(), nil
}

// buildHTMLStageReports converts pipeline.StageResult values to the richer
// htmlStageReport type that includes a pre-formatted duration string.
func buildHTMLStageReports(stages []pipeline.StageResult) []htmlStageReport {
	out := make([]htmlStageReport, len(stages))
	for i, s := range stages {
		out[i] = htmlStageReport{
			Name:              s.Stage.Name,
			Status:            s.Status,
			DurationFormatted: formatDuration(s.Duration),
			Stats:             s.Stats,
		}
	}
	return out
}

// formatDuration produces a human-friendly duration string, e.g. "1m 23s".
// Sub-second durations are shown in milliseconds.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm %ds", m, s)
	}
}
