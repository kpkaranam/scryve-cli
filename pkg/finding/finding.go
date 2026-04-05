// Package finding defines the universal data model that all Scryve tool
// integrations normalize their output into. Every adapter (nmap, nuclei,
// nikto, etc.) must convert raw tool output to a []Finding before returning
// results to the pipeline.
package finding

import "time"

// Finding is the canonical, tool-agnostic representation of a single security
// observation produced during a scan. Fields that are not applicable for a
// given tool should be left at their zero values.
type Finding struct {
	// ID is a caller-assigned unique identifier (e.g. UUIDv4 or sequential).
	ID string `json:"id" yaml:"id"`

	// Title is a short, human-readable name for the finding.
	Title string `json:"title" yaml:"title"`

	// Description provides a detailed explanation of the finding and its impact.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Severity is the risk classification. Use SeverityFromCVSS or
	// SeverityFromString to derive this value.
	Severity Severity `json:"severity" yaml:"severity"`

	// CVSS is the Common Vulnerability Scoring System base score (0.0–10.0).
	// A value of 0 means the score was not computed.
	CVSS float64 `json:"cvss,omitempty" yaml:"cvss,omitempty"`

	// CWE is the Common Weakness Enumeration identifier (e.g. "CWE-89").
	CWE string `json:"cwe,omitempty" yaml:"cwe,omitempty"`

	// CVE is the Common Vulnerabilities and Exposures identifier (e.g. "CVE-2021-1234").
	CVE string `json:"cve,omitempty" yaml:"cve,omitempty"`

	// Tool is the name of the scanning tool that produced this finding.
	Tool string `json:"tool,omitempty" yaml:"tool,omitempty"`

	// Host is the DNS hostname of the affected target.
	Host string `json:"host,omitempty" yaml:"host,omitempty"`

	// IP is the IPv4 or IPv6 address of the affected target.
	IP string `json:"ip,omitempty" yaml:"ip,omitempty"`

	// Port is the TCP/UDP port number. 0 means port is not applicable.
	Port int `json:"port,omitempty" yaml:"port,omitempty"`

	// Path is the URL path or file path where the issue was identified.
	Path string `json:"path,omitempty" yaml:"path,omitempty"`

	// Protocol is the application-layer protocol (e.g. "https", "ftp").
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Evidence holds the proof-of-concept data for this finding.
	Evidence Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`

	// Fingerprint is a SHA-256 hash derived from stable fields (tool, cwe,
	// host, port, path). Populated by Fingerprint(). Used for deduplication.
	Fingerprint string `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`

	// FirstSeen is the timestamp when this finding was first observed.
	FirstSeen time.Time `json:"first_seen,omitempty" yaml:"first_seen,omitempty"`

	// LastSeen is the timestamp when this finding was most recently observed.
	// Updated by Deduplicate() when a duplicate is found on a later scan.
	LastSeen time.Time `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`

	// Tags are free-form labels for grouping and filtering findings.
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`

	// Metadata holds arbitrary tool-specific key-value pairs that do not fit
	// the structured fields above.
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Compliance lists the regulatory/compliance controls affected by this finding.
	Compliance []ComplianceMapping `json:"compliance,omitempty" yaml:"compliance,omitempty"`
}

// Evidence holds the proof-of-concept data that substantiates a Finding.
// Fields are all optional; populate only what is available for the tool.
type Evidence struct {
	// Request is the raw HTTP request (or equivalent) that triggered the issue.
	Request string `json:"request,omitempty" yaml:"request,omitempty"`

	// Response is the raw HTTP response (or equivalent) received from the target.
	Response string `json:"response,omitempty" yaml:"response,omitempty"`

	// Screenshot is a file path or base64-encoded image of the evidence.
	Screenshot string `json:"screenshot,omitempty" yaml:"screenshot,omitempty"`

	// Proof is a free-text description or snippet proving exploitation.
	Proof string `json:"proof,omitempty" yaml:"proof,omitempty"`

	// URL is the full URL that was tested or that demonstrates the issue.
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
}

// ComplianceMapping associates a Finding with a specific control in a
// regulatory or security framework (e.g. OWASP, PCI-DSS, ISO 27001).
type ComplianceMapping struct {
	// Framework is the name of the compliance framework (e.g. "OWASP", "PCI-DSS").
	Framework string `json:"framework" yaml:"framework"`

	// ControlID is the identifier of the specific control within the framework.
	ControlID string `json:"control_id" yaml:"control_id"`

	// Status indicates the compliance state: "pass", "fail", or "not-applicable".
	Status string `json:"status" yaml:"status"`
}

// FindingResult bundles a collection of normalised findings with an aggregated
// summary. It is the standard return type from pipeline stages that produce
// findings.
type FindingResult struct {
	// Findings is the deduplicated, normalised list of findings.
	Findings []Finding `json:"findings" yaml:"findings"`

	// Summary is a breakdown of finding counts by severity level.
	Summary ResultSummary `json:"summary" yaml:"summary"`
}

// ResultSummary holds per-severity counts for a set of findings. It is used
// for quick dashboard display and report generation.
type ResultSummary struct {
	// Total is the total number of findings.
	Total int `json:"total" yaml:"total"`

	// Critical is the count of findings with SeverityCritical.
	Critical int `json:"critical" yaml:"critical"`

	// High is the count of findings with SeverityHigh.
	High int `json:"high" yaml:"high"`

	// Medium is the count of findings with SeverityMedium.
	Medium int `json:"medium" yaml:"medium"`

	// Low is the count of findings with SeverityLow.
	Low int `json:"low" yaml:"low"`

	// Info is the count of findings with SeverityInfo.
	Info int `json:"info" yaml:"info"`
}
