package finding_test

import (
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/finding"
)

// TestFinding_FieldAssignment verifies that all Finding fields can be set and
// read back correctly. This guards against typos in field names or type mismatches.
func TestFinding_FieldAssignment(t *testing.T) {
	now := time.Now().UTC()

	f := finding.Finding{
		ID:          "find-001",
		Title:       "SQL Injection",
		Description: "User input unsanitized",
		Severity:    finding.SeverityCritical,
		CVSS:        9.8,
		CWE:         "CWE-89",
		CVE:         "CVE-2021-1234",
		Tool:        "sqlmap",
		Host:        "example.com",
		IP:          "93.184.216.34",
		Port:        443,
		Path:        "/api/users",
		Protocol:    "https",
		Evidence: finding.Evidence{
			Request:    "GET /api/users?id=1'",
			Response:   "500 Internal Server Error",
			Screenshot: "/tmp/screenshot.png",
			Proof:      "error in SQL query",
			URL:        "https://example.com/api/users?id=1'",
		},
		Fingerprint: "abc123",
		FirstSeen:   now,
		LastSeen:    now,
		Tags:        []string{"injection", "database"},
		Metadata:    map[string]interface{}{"confidence": "high"},
		Compliance: []finding.ComplianceMapping{
			{Framework: "OWASP", ControlID: "A03:2021", Status: "fail"},
		},
	}

	if f.ID != "find-001" {
		t.Errorf("ID = %q, want %q", f.ID, "find-001")
	}
	if f.CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8", f.CVSS)
	}
	if f.Port != 443 {
		t.Errorf("Port = %d, want 443", f.Port)
	}
	if f.Evidence.URL != "https://example.com/api/users?id=1'" {
		t.Errorf("Evidence.URL = %q", f.Evidence.URL)
	}
	if len(f.Tags) != 2 {
		t.Errorf("Tags len = %d, want 2", len(f.Tags))
	}
	if len(f.Compliance) != 1 {
		t.Errorf("Compliance len = %d, want 1", len(f.Compliance))
	}
	if f.Compliance[0].Framework != "OWASP" {
		t.Errorf("Compliance[0].Framework = %q, want %q", f.Compliance[0].Framework, "OWASP")
	}
	meta, ok := f.Metadata["confidence"]
	if !ok {
		t.Error("Metadata key 'confidence' not found")
	}
	if meta != "high" {
		t.Errorf("Metadata['confidence'] = %v, want 'high'", meta)
	}
}

// TestFindingResult_Summary verifies the FindingResult aggregation struct.
func TestFindingResult_Summary(t *testing.T) {
	findings := []finding.Finding{
		{Severity: finding.SeverityCritical},
		{Severity: finding.SeverityHigh},
	}
	summary := finding.ResultSummary{Total: 2, Critical: 1, High: 1}
	result := finding.FindingResult{
		Findings: findings,
		Summary:  summary,
	}

	if len(result.Findings) != 2 {
		t.Errorf("FindingResult.Findings len = %d, want 2", len(result.Findings))
	}
	if result.Summary.Total != 2 {
		t.Errorf("FindingResult.Summary.Total = %d, want 2", result.Summary.Total)
	}
	if result.Summary.Critical != 1 {
		t.Errorf("FindingResult.Summary.Critical = %d, want 1", result.Summary.Critical)
	}
}

// TestEvidence_ZeroValue ensures Evidence can be used with all zero values
// without causing panics.
func TestEvidence_ZeroValue(t *testing.T) {
	var e finding.Evidence
	if e.Request != "" || e.Response != "" || e.Screenshot != "" ||
		e.Proof != "" || e.URL != "" {
		t.Error("zero-value Evidence has unexpected non-empty fields")
	}
}

// TestComplianceMapping_Fields verifies field names on ComplianceMapping.
func TestComplianceMapping_Fields(t *testing.T) {
	cm := finding.ComplianceMapping{
		Framework: "PCI-DSS",
		ControlID: "6.5.1",
		Status:    "pass",
	}
	if cm.Framework != "PCI-DSS" {
		t.Errorf("Framework = %q", cm.Framework)
	}
	if cm.ControlID != "6.5.1" {
		t.Errorf("ControlID = %q", cm.ControlID)
	}
	if cm.Status != "pass" {
		t.Errorf("Status = %q", cm.Status)
	}
}
