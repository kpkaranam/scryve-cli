package compliance

import (
	_ "embed"
	"strings"

	"github.com/scryve/scryve/pkg/finding"
)

//go:embed data/pci-dss-4.0.yaml
var pciDSS40YAML []byte

// emailKeywords are title/tag substrings that indicate an email-security
// finding (SPF, DKIM, DMARC). Such findings map to requirement 4.2.1.
var emailKeywords = []string{"spf", "dkim", "dmarc"}

// highSeverityFallbackControl is the control ID used when a finding has
// critical or high severity but no CWE or CVE.
const highSeverityFallbackControl = "6.3.1"

// cveControl is the control ID that all CVE-tagged findings map to.
const cveControl = "6.3.1"

// emailControl is the control ID for email-security findings.
const emailControl = "4.2.1"

// NewPCIDSSMapper constructs a ComplianceMapper from the embedded
// pkg/compliance/data/pci-dss-4.0.yaml file. The binary is self-contained;
// no external files are required at runtime.
func NewPCIDSSMapper() (ComplianceMapper, error) {
	fw, err := parseFrameworkYAML(pciDSS40YAML)
	if err != nil {
		return nil, err
	}

	controls := make([]Control, len(fw.Controls))
	for i, c := range fw.Controls {
		controls[i] = Control(c)
	}

	m := &pciDSSMapper{
		baseMapper: &baseMapper{
			framework:   fw.Framework,
			version:     fw.Version,
			description: fw.Description,
			controls:    controls,
		},
	}
	m.buildIndex()
	return m, nil
}

// pciDSSMapper is the PCI DSS 4.0 implementation of ComplianceMapper.
// It extends baseMapper with PCI-specific CVE, email-security, and
// severity-based fallback logic.
type pciDSSMapper struct {
	*baseMapper
	// cweIndex maps a normalised CWE ID (e.g. "CWE-79") to a list of
	// control IDs that reference it.
	cweIndex map[string][]string
}

// buildIndex pre-computes cweIndex from the control list so that MapFinding
// runs in O(k) time where k is the number of matching controls.
func (m *pciDSSMapper) buildIndex() {
	m.cweIndex = make(map[string][]string)
	for _, c := range m.controls {
		for _, cwe := range c.CWEs {
			norm := normalizeCWE(cwe)
			m.cweIndex[norm] = append(m.cweIndex[norm], c.ID)
		}
	}
}

// MapFinding returns all PCI DSS 4.0 control mappings for f. The mapping logic
// applies four rules in order, deduplicating control IDs across all rules:
//
//  1. CWE lookup  — if f.CWE is non-empty, look up all controls that list it.
//  2. CVE rule    — if f.CVE is non-empty, map to requirement 6.3.1.
//  3. Email rule  — if f.Title or f.Tags contain SPF/DKIM/DMARC keywords,
//     map to requirement 4.2.1.
//  4. Severity fallback — if f.Severity is critical or high and f.CWE is
//     empty and f.CVE is empty, map to requirement 6.3.1.
//
// Every returned mapping has Framework="pci-dss-4.0" and Status="fail".
func (m *pciDSSMapper) MapFinding(f *finding.Finding) []finding.ComplianceMapping {
	if f == nil {
		return nil
	}

	seen := make(map[string]bool)
	var result []finding.ComplianceMapping

	addMapping := func(controlID string) {
		if seen[controlID] {
			return
		}
		seen[controlID] = true
		result = append(result, finding.ComplianceMapping{
			Framework: m.framework,
			ControlID: controlID,
			Status:    "fail",
		})
	}

	// Rule 1: CWE lookup.
	if f.CWE != "" {
		norm := normalizeCWE(f.CWE)
		for _, controlID := range m.cweIndex[norm] {
			addMapping(controlID)
		}
	}

	// Rule 2: CVE → 6.3.1.
	if f.CVE != "" {
		addMapping(cveControl)
	}

	// Rule 3: Email-security keywords → 4.2.1.
	if isEmailFinding(f) {
		addMapping(emailControl)
	}

	// Rule 4: Severity fallback for critical/high with no CWE and no CVE.
	if f.CWE == "" && f.CVE == "" {
		if f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh {
			addMapping(highSeverityFallbackControl)
		}
	}

	return result
}

// MapFindings enriches each finding in the slice by appending all applicable
// PCI DSS mappings to f.Compliance. Pre-existing mappings for other frameworks
// are preserved.
func (m *pciDSSMapper) MapFindings(findings []finding.Finding) []finding.Finding {
	for i := range findings {
		mappings := m.MapFinding(&findings[i])
		findings[i].Compliance = append(findings[i].Compliance, mappings...)
	}
	return findings
}

// ---------------------------------------------------------------------------
// baseMapper — generic ComplianceMapper used for non-PCI frameworks loaded
// via LoadMapper / LoadAllMappers.
// ---------------------------------------------------------------------------

// baseMapper is a minimal ComplianceMapper implementation backed by a slice of
// Control values. It performs CWE lookups only (no CVE or email rules).
type baseMapper struct {
	framework   string
	version     string
	description string
	controls    []Control
	// cweIndex is built lazily by ensureIndex.
	cweIndex map[string][]string
}

func (b *baseMapper) Framework() string { return b.framework }
func (b *baseMapper) Version() string   { return b.version }

// Controls returns a deep copy of the control slice.
func (b *baseMapper) Controls() []Control {
	out := make([]Control, len(b.controls))
	copy(out, b.controls)
	return out
}

// ensureIndex lazily builds the CWE index.
func (b *baseMapper) ensureIndex() {
	if b.cweIndex != nil {
		return
	}
	b.cweIndex = make(map[string][]string)
	for _, c := range b.controls {
		for _, cwe := range c.CWEs {
			norm := normalizeCWE(cwe)
			b.cweIndex[norm] = append(b.cweIndex[norm], c.ID)
		}
	}
}

// MapFinding performs a CWE lookup only (no CVE/email/severity rules).
func (b *baseMapper) MapFinding(f *finding.Finding) []finding.ComplianceMapping {
	if f == nil {
		return nil
	}
	b.ensureIndex()

	seen := make(map[string]bool)
	var result []finding.ComplianceMapping

	if f.CWE != "" {
		norm := normalizeCWE(f.CWE)
		for _, controlID := range b.cweIndex[norm] {
			if seen[controlID] {
				continue
			}
			seen[controlID] = true
			result = append(result, finding.ComplianceMapping{
				Framework: b.framework,
				ControlID: controlID,
				Status:    "fail",
			})
		}
	}
	return result
}

// MapFindings enriches each finding with CWE-based mappings.
func (b *baseMapper) MapFindings(findings []finding.Finding) []finding.Finding {
	for i := range findings {
		mappings := b.MapFinding(&findings[i])
		findings[i].Compliance = append(findings[i].Compliance, mappings...)
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// normalizeCWE normalises a CWE identifier to uppercase "CWE-NNN" form.
// "79", "cwe-79", and "CWE-79" all normalise to "CWE-79".
func normalizeCWE(raw string) string {
	upper := strings.ToUpper(strings.TrimSpace(raw))
	if strings.HasPrefix(upper, "CWE-") {
		return upper
	}
	return "CWE-" + upper
}

// isEmailFinding returns true if f appears to be an email-security finding
// (SPF, DKIM, or DMARC) based on its title or tags.
func isEmailFinding(f *finding.Finding) bool {
	titleLower := strings.ToLower(f.Title)
	for _, kw := range emailKeywords {
		if strings.Contains(titleLower, kw) {
			return true
		}
	}
	for _, tag := range f.Tags {
		tagLower := strings.ToLower(tag)
		for _, kw := range emailKeywords {
			if strings.Contains(tagLower, kw) {
				return true
			}
		}
	}
	return false
}
