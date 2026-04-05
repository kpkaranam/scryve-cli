package report

import (
	"github.com/scryve/scryve/pkg/compliance"
	"github.com/scryve/scryve/pkg/finding"
)

// complianceReporterAdapter wraps a compliance.ComplianceMapper so it satisfies
// the report.ComplianceReporter interface. This avoids a direct dependency on
// the compliance package's concrete types from within the report generation
// functions, keeping the report package testable without a real mapper.
type complianceReporterAdapter struct {
	mapper compliance.ComplianceMapper
}

// NewComplianceReporter wraps a compliance.ComplianceMapper and returns a
// ComplianceReporter suitable for passing to GenerateJSON and GenerateHTML.
func NewComplianceReporter(mapper compliance.ComplianceMapper) ComplianceReporter {
	return &complianceReporterAdapter{mapper: mapper}
}

func (a *complianceReporterAdapter) Framework() string { return a.mapper.Framework() }
func (a *complianceReporterAdapter) Version() string   { return a.mapper.Version() }

func (a *complianceReporterAdapter) MapFindings(findings []finding.Finding) []finding.Finding {
	return a.mapper.MapFindings(findings)
}

// Controls converts compliance.Control values to report.Control values.
func (a *complianceReporterAdapter) Controls() []Control {
	src := a.mapper.Controls()
	out := make([]Control, len(src))
	for i, c := range src {
		out[i] = Control{
			ID:          c.ID,
			Title:       c.Title,
			Description: c.Description,
			CWEs:        c.CWEs,
		}
	}
	return out
}
