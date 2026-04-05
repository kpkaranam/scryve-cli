// Package finding_test — tests for per-tool finding normalization (TASK-016).
package finding_test

import (
	"strings"
	"testing"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/finding"
)

// ---------------------------------------------------------------------------
// NormalizeNuclei — full JSON with CVE, CWE, CVSS, matched-at, curl-command
// ---------------------------------------------------------------------------

func TestNormalizeNuclei_Full(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "nuclei",
		ToolOutput: map[string]interface{}{
			"template-id":  "CVE-2021-44228",
			"host":         "https://api.example.com",
			"ip":           "93.184.216.34",
			"port":         "443",
			"matched-at":   "https://api.example.com/api/users?id=1",
			"curl-command": "curl -X GET 'https://api.example.com/api/users?id=1'",
			"info": map[string]interface{}{
				"name":        "Log4Shell Remote Code Execution",
				"description": "Apache Log4j2 JNDI features do not protect against LDAP attacks.",
				"severity":    "critical",
				"tags":        []interface{}{"cve", "log4j", "rce"},
				"classification": map[string]interface{}{
					"cvss-score": 10.0,
					"cwe-id":     []interface{}{"CWE-917"},
					"cve-id":     []interface{}{"CVE-2021-44228"},
				},
			},
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "nuclei" {
		t.Errorf("Tool = %q, want %q", f.Tool, "nuclei")
	}
	if f.Title != "Log4Shell Remote Code Execution" {
		t.Errorf("Title = %q, want %q", f.Title, "Log4Shell Remote Code Execution")
	}
	if f.Description != "Apache Log4j2 JNDI features do not protect against LDAP attacks." {
		t.Errorf("Description = %q", f.Description)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("Severity = %q, want %q", f.Severity, finding.SeverityCritical)
	}
	if f.CVSS != 10.0 {
		t.Errorf("CVSS = %v, want 10.0", f.CVSS)
	}
	if f.CWE != "CWE-917" {
		t.Errorf("CWE = %q, want %q", f.CWE, "CWE-917")
	}
	if f.CVE != "CVE-2021-44228" {
		t.Errorf("CVE = %q, want %q", f.CVE, "CVE-2021-44228")
	}
	if f.Host != "https://api.example.com" {
		t.Errorf("Host = %q, want %q", f.Host, "https://api.example.com")
	}
	if f.IP != "93.184.216.34" {
		t.Errorf("IP = %q, want %q", f.IP, "93.184.216.34")
	}
	if f.Port != 443 {
		t.Errorf("Port = %d, want 443", f.Port)
	}
	if f.Path != "https://api.example.com/api/users?id=1" {
		t.Errorf("Path = %q", f.Path)
	}
	if f.Evidence.URL != "https://api.example.com/api/users?id=1" {
		t.Errorf("Evidence.URL = %q", f.Evidence.URL)
	}
	if f.Evidence.Proof != "curl -X GET 'https://api.example.com/api/users?id=1'" {
		t.Errorf("Evidence.Proof = %q", f.Evidence.Proof)
	}
	if len(f.Tags) != 3 {
		t.Errorf("Tags len = %d, want 3: %v", len(f.Tags), f.Tags)
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint must be populated")
	}
	if f.FirstSeen.IsZero() {
		t.Error("FirstSeen must be populated")
	}
	if f.LastSeen.IsZero() {
		t.Error("LastSeen must be populated")
	}
}

// ---------------------------------------------------------------------------
// NormalizeNuclei — minimal JSON (no classification block)
// ---------------------------------------------------------------------------

func TestNormalizeNuclei_Minimal(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "nuclei",
		ToolOutput: map[string]interface{}{
			"template-id": "self-signed-ssl",
			"host":        "example.com",
			"matched-at":  "https://example.com",
			"info": map[string]interface{}{
				"name":     "Self-Signed SSL Certificate",
				"severity": "low",
			},
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "nuclei" {
		t.Errorf("Tool = %q, want %q", f.Tool, "nuclei")
	}
	if f.Title != "Self-Signed SSL Certificate" {
		t.Errorf("Title = %q, want %q", f.Title, "Self-Signed SSL Certificate")
	}
	if f.Severity != finding.SeverityLow {
		t.Errorf("Severity = %q, want %q", f.Severity, finding.SeverityLow)
	}
	if f.CVSS != 0.0 {
		t.Errorf("CVSS = %v, want 0.0 (not set)", f.CVSS)
	}
	if f.CWE != "" {
		t.Errorf("CWE = %q, want empty (no classification)", f.CWE)
	}
	if f.CVE != "" {
		t.Errorf("CVE = %q, want empty (no classification)", f.CVE)
	}
	if f.Host != "example.com" {
		t.Errorf("Host = %q, want %q", f.Host, "example.com")
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint must be populated even for minimal results")
	}
}

// ---------------------------------------------------------------------------
// NormalizeHTTPX — with technology detection output
// ---------------------------------------------------------------------------

func TestNormalizeHTTPX_WithTechDetection(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "httpx",
		ToolOutput: map[string]interface{}{
			"url":          "https://api.example.com",
			"status_code":  float64(200),
			"title":        "API Gateway",
			"technologies": []interface{}{"nginx", "Go"},
			"cdn":          false,
			"cdn_name":     "",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "httpx" {
		t.Errorf("Tool = %q, want %q", f.Tool, "httpx")
	}
	if !strings.Contains(f.Title, "HTTP Service") {
		t.Errorf("Title = %q, want it to contain 'HTTP Service'", f.Title)
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("Severity = %q, want %q (asset discovery)", f.Severity, finding.SeverityInfo)
	}
	if f.Host != "api.example.com" {
		t.Errorf("Host = %q, want %q", f.Host, "api.example.com")
	}
	if f.Port != 443 {
		t.Errorf("Port = %d, want 443", f.Port)
	}
	if f.Protocol != "https" {
		t.Errorf("Protocol = %q, want %q", f.Protocol, "https")
	}
	if len(f.Tags) < 2 {
		t.Errorf("Tags len = %d, want at least 2 (technologies): %v", len(f.Tags), f.Tags)
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint must be populated")
	}
}

// ---------------------------------------------------------------------------
// NormalizeHTTPX — URL with page title as fallback
// ---------------------------------------------------------------------------

func TestNormalizeHTTPX_TitleFallback(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "httpx",
		ToolOutput: map[string]interface{}{
			"url":          "http://sub.example.com:8080",
			"status_code":  float64(301),
			"title":        "",
			"technologies": []interface{}{},
			"cdn":          false,
		},
	}

	f := finding.NormalizeRawFinding(raw)

	// Title should fall back to URL when page title is empty.
	if !strings.Contains(f.Title, "HTTP Service") {
		t.Errorf("Title = %q, want it to contain 'HTTP Service'", f.Title)
	}
	if f.Host != "sub.example.com" {
		t.Errorf("Host = %q, want %q", f.Host, "sub.example.com")
	}
	if f.Port != 8080 {
		t.Errorf("Port = %d, want 8080", f.Port)
	}
	if f.Protocol != "http" {
		t.Errorf("Protocol = %q, want %q", f.Protocol, "http")
	}
}

// ---------------------------------------------------------------------------
// NormalizeNaabu — port scan output
// ---------------------------------------------------------------------------

func TestNormalizeNaabu_OpenPort(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "naabu",
		ToolOutput: map[string]interface{}{
			"host":     "api.example.com",
			"port":     "8443",
			"protocol": "tcp",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "naabu" {
		t.Errorf("Tool = %q, want %q", f.Tool, "naabu")
	}
	if f.Title != "Open Port: api.example.com:8443" {
		t.Errorf("Title = %q, want %q", f.Title, "Open Port: api.example.com:8443")
	}
	if f.Host != "api.example.com" {
		t.Errorf("Host = %q, want %q", f.Host, "api.example.com")
	}
	if f.Port != 8443 {
		t.Errorf("Port = %d, want 8443", f.Port)
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("Severity = %q, want %q", f.Severity, finding.SeverityInfo)
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint must be populated")
	}
}

// ---------------------------------------------------------------------------
// NormalizeSubfinder — subdomain discovery output
// ---------------------------------------------------------------------------

func TestNormalizeSubfinder_Subdomain(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "subfinder",
		ToolOutput: map[string]interface{}{
			"host": "staging.example.com",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "subfinder" {
		t.Errorf("Tool = %q, want %q", f.Tool, "subfinder")
	}
	if f.Title != "Subdomain: staging.example.com" {
		t.Errorf("Title = %q, want %q", f.Title, "Subdomain: staging.example.com")
	}
	if f.Host != "staging.example.com" {
		t.Errorf("Host = %q, want %q", f.Host, "staging.example.com")
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("Severity = %q, want %q", f.Severity, finding.SeverityInfo)
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint must be populated")
	}
}

// ---------------------------------------------------------------------------
// NormalizeRawFinding — dispatch to correct normalizer by ToolName
// ---------------------------------------------------------------------------

func TestNormalizeRawFinding_DispatchNuclei(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "nuclei",
		ToolOutput: map[string]interface{}{
			"info": map[string]interface{}{
				"name":     "Test Template",
				"severity": "medium",
			},
			"host":       "example.com",
			"matched-at": "https://example.com/test",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "nuclei" {
		t.Errorf("Tool = %q, want nuclei", f.Tool)
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	// Nuclei normalizer extracts title from info.name — not present in a generic field.
	if f.Title != "Test Template" {
		t.Errorf("Title = %q, want 'Test Template' (from info.name)", f.Title)
	}
}

func TestNormalizeRawFinding_DispatchHTTPX(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "httpx",
		ToolOutput: map[string]interface{}{
			"url":   "https://example.com",
			"title": "Home",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "httpx" {
		t.Errorf("Tool = %q, want httpx", f.Tool)
	}
	if !strings.Contains(f.Title, "HTTP Service") {
		t.Errorf("Title = %q, expected dispatch to httpx normalizer", f.Title)
	}
}

func TestNormalizeRawFinding_DispatchNaabu(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "naabu",
		ToolOutput: map[string]interface{}{
			"host": "example.com",
			"port": "80",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "naabu" {
		t.Errorf("Tool = %q, want naabu", f.Tool)
	}
	if !strings.Contains(f.Title, "Open Port") {
		t.Errorf("Title = %q, expected dispatch to naabu normalizer", f.Title)
	}
}

func TestNormalizeRawFinding_DispatchSubfinder(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "subfinder",
		ToolOutput: map[string]interface{}{
			"host": "api.example.com",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "subfinder" {
		t.Errorf("Tool = %q, want subfinder", f.Tool)
	}
	if !strings.Contains(f.Title, "Subdomain") {
		t.Errorf("Title = %q, expected dispatch to subfinder normalizer", f.Title)
	}
}

func TestNormalizeRawFinding_UnknownTool(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "custom-tool",
		ToolOutput: map[string]interface{}{
			"finding": "something interesting",
			"host":    "target.example.com",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Tool != "custom-tool" {
		t.Errorf("Tool = %q, want custom-tool", f.Tool)
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("Severity = %q, want info for unknown tool", f.Severity)
	}
	// Unknown tool output must be stored in Metadata for later inspection.
	if f.Metadata == nil {
		t.Error("Metadata must not be nil for unknown tools")
	}
	if _, ok := f.Metadata["tool_output"]; !ok {
		t.Error("Metadata must contain 'tool_output' key for unknown tools")
	}
	if f.Fingerprint == "" {
		t.Error("Fingerprint must be populated even for unknown tools")
	}
}

// ---------------------------------------------------------------------------
// Fingerprint auto-generation
// ---------------------------------------------------------------------------

func TestNormalizeRawFinding_FingerprintAutoGenerated(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "subfinder",
		ToolOutput: map[string]interface{}{
			"host": "fp.example.com",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if f.Fingerprint == "" {
		t.Fatal("Fingerprint should be auto-generated by NormalizeRawFinding")
	}

	// Same input always produces the same fingerprint.
	f2 := finding.NormalizeRawFinding(raw)
	if f.Fingerprint != f2.Fingerprint {
		t.Errorf("Fingerprint not deterministic: %q vs %q", f.Fingerprint, f2.Fingerprint)
	}
}

// ---------------------------------------------------------------------------
// NormalizeNuclei — tags are extracted from info.tags
// ---------------------------------------------------------------------------

func TestNormalizeNuclei_TagsExtraction(t *testing.T) {
	raw := adapter.RawFinding{
		ToolName: "nuclei",
		ToolOutput: map[string]interface{}{
			"info": map[string]interface{}{
				"name":     "XSS Probe",
				"severity": "medium",
				"tags":     []interface{}{"xss", "injection", "owasp-a07"},
			},
			"host":       "example.com",
			"matched-at": "https://example.com/search?q=test",
		},
	}

	f := finding.NormalizeRawFinding(raw)

	if len(f.Tags) != 3 {
		t.Errorf("Tags = %v, want 3 entries", f.Tags)
	}
	found := make(map[string]bool)
	for _, tag := range f.Tags {
		found[tag] = true
	}
	for _, expected := range []string{"xss", "injection", "owasp-a07"} {
		if !found[expected] {
			t.Errorf("tag %q missing from Tags %v", expected, f.Tags)
		}
	}
}

// ---------------------------------------------------------------------------
// NormalizeNuclei — port field is parsed from string to int
// ---------------------------------------------------------------------------

func TestNormalizeNuclei_PortParsing(t *testing.T) {
	tests := []struct {
		name     string
		portVal  interface{}
		wantPort int
	}{
		{"string port", "8080", 8080},
		{"numeric port (float64)", float64(443), 443},
		{"empty string", "", 0},
		{"missing port", nil, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			toolOutput := map[string]interface{}{
				"info": map[string]interface{}{
					"name":     "Test",
					"severity": "info",
				},
				"host":       "example.com",
				"matched-at": "https://example.com",
			}
			if tc.portVal != nil {
				toolOutput["port"] = tc.portVal
			}

			raw := adapter.RawFinding{
				ToolName:   "nuclei",
				ToolOutput: toolOutput,
			}
			f := finding.NormalizeRawFinding(raw)
			if f.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", f.Port, tc.wantPort)
			}
		})
	}
}
