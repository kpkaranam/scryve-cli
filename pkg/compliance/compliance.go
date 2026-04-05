// Package compliance provides a YAML-driven system for mapping security
// findings to regulatory compliance framework controls. Each framework is
// represented by a ComplianceMapper that can annotate findings with the
// relevant controls they violate.
//
// Usage:
//
//	mapper, err := compliance.NewPCIDSSMapper()
//	enriched := mapper.MapFindings(myFindings)
package compliance

import "github.com/scryve/scryve/pkg/finding"

// ComplianceMapper is the interface that every compliance framework adapter
// must implement. All mapper implementations must be safe for concurrent use.
type ComplianceMapper interface {
	// Framework returns the canonical framework identifier (e.g. "pci-dss-4.0").
	// This string is stored verbatim in ComplianceMapping.Framework.
	Framework() string

	// Version returns the version string of the framework (e.g. "4.0").
	Version() string

	// MapFinding returns all ComplianceMapping entries that apply to the given
	// finding. If f is nil the method returns nil without panicking.
	// Returned mappings always have Status="fail".
	MapFinding(f *finding.Finding) []finding.ComplianceMapping

	// MapFindings enriches every finding in the slice by appending all
	// applicable compliance mappings to f.Compliance. It preserves any
	// pre-existing mappings for other frameworks. The enriched findings are
	// returned; the input slice itself may be modified in-place.
	MapFindings(findings []finding.Finding) []finding.Finding

	// Controls returns the full list of controls defined in this framework's
	// mapping data. The returned slice is a copy; callers may modify it freely.
	Controls() []Control
}

// Control describes a single requirement within a compliance framework.
type Control struct {
	// ID is the control's identifier within the framework (e.g. "6.2.4").
	ID string

	// Title is the short human-readable name of the control.
	Title string

	// Description provides additional context for the control.
	Description string

	// CWEs is the list of CWE identifiers (e.g. "CWE-79") that, when present
	// in a finding, indicate a violation of this control.
	CWEs []string
}
