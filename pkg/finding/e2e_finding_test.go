// E2E tests for finding normalization, dedup, and severity — Story 3.3
package finding_test

import (
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/finding"
)

// --------------------------------------------------------------------------
// Severity boundary tests
// --------------------------------------------------------------------------

func TestE2E_SeverityBoundary_0_0(t *testing.T) {
	if got := finding.SeverityFromCVSS(0.0); got != finding.SeverityInfo {
		t.Errorf("CVSS 0.0: got %s, want %s", got, finding.SeverityInfo)
	}
}

func TestE2E_SeverityBoundary_0_1(t *testing.T) {
	if got := finding.SeverityFromCVSS(0.1); got != finding.SeverityLow {
		t.Errorf("CVSS 0.1: got %s, want %s", got, finding.SeverityLow)
	}
}

func TestE2E_SeverityBoundary_3_9(t *testing.T) {
	if got := finding.SeverityFromCVSS(3.9); got != finding.SeverityLow {
		t.Errorf("CVSS 3.9: got %s, want %s", got, finding.SeverityLow)
	}
}

func TestE2E_SeverityBoundary_4_0(t *testing.T) {
	if got := finding.SeverityFromCVSS(4.0); got != finding.SeverityMedium {
		t.Errorf("CVSS 4.0: got %s, want %s", got, finding.SeverityMedium)
	}
}

func TestE2E_SeverityBoundary_6_9(t *testing.T) {
	if got := finding.SeverityFromCVSS(6.9); got != finding.SeverityMedium {
		t.Errorf("CVSS 6.9: got %s, want %s", got, finding.SeverityMedium)
	}
}

func TestE2E_SeverityBoundary_7_0(t *testing.T) {
	if got := finding.SeverityFromCVSS(7.0); got != finding.SeverityHigh {
		t.Errorf("CVSS 7.0: got %s, want %s", got, finding.SeverityHigh)
	}
}

func TestE2E_SeverityBoundary_8_9(t *testing.T) {
	if got := finding.SeverityFromCVSS(8.9); got != finding.SeverityHigh {
		t.Errorf("CVSS 8.9: got %s, want %s", got, finding.SeverityHigh)
	}
}

func TestE2E_SeverityBoundary_9_0(t *testing.T) {
	if got := finding.SeverityFromCVSS(9.0); got != finding.SeverityCritical {
		t.Errorf("CVSS 9.0: got %s, want %s", got, finding.SeverityCritical)
	}
}

func TestE2E_SeverityBoundary_10_0(t *testing.T) {
	if got := finding.SeverityFromCVSS(10.0); got != finding.SeverityCritical {
		t.Errorf("CVSS 10.0: got %s, want %s", got, finding.SeverityCritical)
	}
}

// --------------------------------------------------------------------------
// Dedup tests
// --------------------------------------------------------------------------

func TestE2E_Dedup_SameFingerprint(t *testing.T) {
	now := time.Now()
	findings := []finding.Finding{
		{Tool: "nuclei", CWE: "CWE-79", Host: "example.com", Port: 443, Path: "/", FirstSeen: now, LastSeen: now},
		{Tool: "nuclei", CWE: "CWE-79", Host: "example.com", Port: 443, Path: "/", FirstSeen: now.Add(time.Hour), LastSeen: now.Add(time.Hour)},
	}

	// Generate fingerprints
	for i := range findings {
		finding.Fingerprint(&findings[i])
	}

	deduped := finding.Deduplicate(findings)
	if len(deduped) != 1 {
		t.Errorf("same fingerprint should dedup to 1, got %d", len(deduped))
	}
}

func TestE2E_Dedup_DifferentHost(t *testing.T) {
	now := time.Now()
	findings := []finding.Finding{
		{Tool: "nuclei", CWE: "CWE-79", Host: "a.com", Port: 443, Path: "/", FirstSeen: now, LastSeen: now},
		{Tool: "nuclei", CWE: "CWE-79", Host: "b.com", Port: 443, Path: "/", FirstSeen: now, LastSeen: now},
	}

	for i := range findings {
		finding.Fingerprint(&findings[i])
	}

	deduped := finding.Deduplicate(findings)
	if len(deduped) != 2 {
		t.Errorf("different hosts should produce 2, got %d", len(deduped))
	}
}

func TestE2E_Dedup_CrossToolSameFinding(t *testing.T) {
	now := time.Now()
	findings := []finding.Finding{
		{Tool: "nuclei", CWE: "CWE-79", Host: "example.com", Port: 443, Path: "/"},
		{Tool: "httpx", CWE: "CWE-79", Host: "example.com", Port: 443, Path: "/"},
	}
	for i := range findings {
		findings[i].FirstSeen = now
		findings[i].LastSeen = now
		finding.Fingerprint(&findings[i])
	}

	deduped := finding.Deduplicate(findings)
	// Fingerprint includes Tool, so different tools = different findings
	if len(deduped) != 2 {
		t.Errorf("different tools should not dedup (fingerprint includes tool), got %d", len(deduped))
	}
}

// --------------------------------------------------------------------------
// Normalization tests
// --------------------------------------------------------------------------

func TestE2E_Normalize_NucleiOutput(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "nuclei",
		ToolOutput: map[string]interface{}{
			"template-id":   "cve-2021-1234",
			"name":          "Test CVE",
			"severity":      "high",
			"host":          "https://example.com",
			"matched-at":    "https://example.com/path",
			"type":          "http",
			"classification": map[string]interface{}{
				"cwe-id":  []interface{}{"CWE-89"},
				"cve-id":  []interface{}{"CVE-2021-1234"},
			},
		},
	}

	f := finding.NormalizeRawFinding(raw)
	if f.Tool != "nuclei" {
		t.Errorf("Tool = %q, want nuclei", f.Tool)
	}
	if f.Title == "" {
		t.Error("Title should not be empty after normalization")
	}
}

func TestE2E_Normalize_MissingFields(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "unknown",
		ToolOutput:     map[string]interface{}{},
	}

	f := finding.NormalizeRawFinding(raw)
	// Should not panic, CWE and CVE should be empty strings
	if f.CWE != "" {
		t.Errorf("CWE should be empty for unknown tool, got %q", f.CWE)
	}
	if f.CVE != "" {
		t.Errorf("CVE should be empty for unknown tool, got %q", f.CVE)
	}
}
