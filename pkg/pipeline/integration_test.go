// Package pipeline_test — integration tests for the full pipeline flow.
//
// These tests exercise the complete pipeline with mock adapters for all five
// standard stages and verify:
//   - Findings pass through with correct fields
//   - Stages execute in order
//   - Data feeds forward between stages
//   - Compliance mapping is applied when configured
package pipeline_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/compliance"
	"github.com/scryve/scryve/pkg/finding"
	"github.com/scryve/scryve/pkg/pipeline"
)

// ---------------------------------------------------------------------------
// Full Five-Stage Integration
// ---------------------------------------------------------------------------

// TestPipeline_Integration_AllFiveStages registers a mock adapter for each of
// the five default stages and verifies the full pipeline produces structured
// findings with correct fields populated.
func TestPipeline_Integration_AllFiveStages(t *testing.T) {
	const testDomain = "integration-test.example.com"

	emailAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDEmail,
		MockName: "email",
		MockFindings: []adapter.RawFinding{
			{
				ToolName: "email",
				ToolOutput: map[string]interface{}{
					"host":     "integration-test.example.com",
					"name":     "Missing SPF Record",
					"severity": "medium",
				},
			},
		},
	}
	subfinderAdapter := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"api.integration-test.example.com", "www.integration-test.example.com"},
	}
	httpxAdapter := &adapter.MockAdapter{
		MockID:        adapter.AdapterIDHTTPX,
		MockName:      "httpx",
		MockLiveHosts: []string{"https://api.integration-test.example.com", "https://www.integration-test.example.com"},
	}
	naabuAdapter := &adapter.MockAdapter{
		MockID:        adapter.AdapterIDNaabu,
		MockName:      "naabu",
		MockOpenPorts: []string{"api.integration-test.example.com:443", "api.integration-test.example.com:80"},
	}
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{
				ToolName: "nuclei",
				ToolOutput: map[string]interface{}{
					"host":     "api.integration-test.example.com",
					"name":     "Log4Shell RCE",
					"severity": "critical",
					"template": "CVE-2021-44228",
				},
			},
			{
				ToolName: "nuclei",
				ToolOutput: map[string]interface{}{
					"host":     "www.integration-test.example.com",
					"name":     "XSS Vulnerability",
					"severity": "high",
				},
			},
		},
	}

	reg := buildRegistry(emailAdapter, subfinderAdapter, httpxAdapter, naabuAdapter, nucleiAdapter)

	stages := pipeline.DefaultStages()
	cfg := pipeline.PipelineConfig{Timeout: 10 * time.Second}

	var progressBuf bytes.Buffer
	p := pipeline.New(reg, cfg, stages)
	result, err := p.Run(context.Background(), testDomain, &progressBuf)

	if err != nil {
		t.Fatalf("integration pipeline returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("integration pipeline returned nil result")
	}

	// All 5 stages must have completed.
	if len(result.Stages) != 5 {
		t.Fatalf("expected 5 stage results, got %d", len(result.Stages))
	}
	for i, sr := range result.Stages {
		if sr.Status != "completed" {
			t.Errorf("stage[%d] %q: status=%q, want %q", i, sr.Stage.Name, sr.Status, "completed")
		}
	}

	// 3 total findings: 1 from email + 2 from nuclei.
	if len(result.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(result.Findings))
	}

	// Verify timing fields are set.
	if result.StartedAt.IsZero() {
		t.Error("StartedAt should not be zero")
	}
	if result.CompletedAt.IsZero() {
		t.Error("CompletedAt should not be zero")
	}
	if result.CompletedAt.Before(result.StartedAt) {
		t.Errorf("CompletedAt %v is before StartedAt %v", result.CompletedAt, result.StartedAt)
	}

	// Progress should have been written.
	if progressBuf.Len() == 0 {
		t.Error("expected progress output from pipeline, got empty buffer")
	}

	// Domain should be propagated.
	if result.Domain != testDomain {
		t.Errorf("result.Domain = %q, want %q", result.Domain, testDomain)
	}
}

// TestPipeline_Integration_FindingFieldsPopulated verifies that findings produced
// by the pipeline have the expected fields populated by the normalise function.
func TestPipeline_Integration_FindingFieldsPopulated(t *testing.T) {
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{
				ToolName: "nuclei",
				ToolOutput: map[string]interface{}{
					"host":        "target.example.com",
					"template-id": "sql-injection-generic",
					"info": map[string]interface{}{
						"name":     "SQL Injection",
						"severity": "critical",
					},
				},
			},
		},
	}

	reg := buildRegistry(nucleiAdapter)
	stages := []pipeline.Stage{
		{Name: "Vulnerability Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	}
	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]

	// Tool field must be set from ToolName.
	if f.Tool != "nuclei" {
		t.Errorf("finding.Tool = %q, want %q", f.Tool, "nuclei")
	}
	// Host must be extracted from ToolOutput["host"].
	if f.Host != "target.example.com" {
		t.Errorf("finding.Host = %q, want %q", f.Host, "target.example.com")
	}
	// Title must be extracted from ToolOutput["name"].
	if f.Title != "SQL Injection" {
		t.Errorf("finding.Title = %q, want %q", f.Title, "SQL Injection")
	}
	// Severity must be parsed from ToolOutput["severity"].
	if f.Severity != finding.SeverityCritical {
		t.Errorf("finding.Severity = %v, want %v", f.Severity, finding.SeverityCritical)
	}
	// FirstSeen and LastSeen should be set.
	if f.FirstSeen.IsZero() {
		t.Error("finding.FirstSeen should not be zero")
	}
	if f.LastSeen.IsZero() {
		t.Error("finding.LastSeen should not be zero")
	}
	// Metadata should contain the raw ToolOutput.
	if f.Metadata == nil {
		t.Error("finding.Metadata should not be nil")
	}
}

// TestPipeline_Integration_TitleFallsBackToTemplate verifies that when
// ToolOutput["name"] is absent, the pipeline uses ToolOutput["template"] for
// the finding title.
func TestPipeline_Integration_TitleFallsBackToTemplate(t *testing.T) {
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{
				ToolName: "nuclei",
				ToolOutput: map[string]interface{}{
					"host":        "target.example.com",
					"template-id": "cve-2021-44228",
					// No "info.name" — should fall back to "template-id".
				},
			},
		},
	}

	reg := buildRegistry(nucleiAdapter)
	p := pipeline.New(reg, pipeline.PipelineConfig{}, []pipeline.Stage{
		{Name: "Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	})
	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Title != "cve-2021-44228" {
		t.Errorf("finding.Title = %q, want %q", result.Findings[0].Title, "cve-2021-44228")
	}
}

// TestPipeline_Integration_TitleNameTakesPrecedenceOverTemplate verifies that
// when both "name" and "template" are present, "name" is used as title.
func TestPipeline_Integration_TitleNameTakesPrecedenceOverTemplate(t *testing.T) {
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{
				ToolName: "nuclei",
				ToolOutput: map[string]interface{}{
					"host":        "target.example.com",
					"template-id": "sqli-template",
					"info": map[string]interface{}{
						"name":     "SQL Injection",
						"severity": "high",
					},
				},
			},
		},
	}

	reg := buildRegistry(nucleiAdapter)
	p := pipeline.New(reg, pipeline.PipelineConfig{}, []pipeline.Stage{
		{Name: "Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	})
	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	// "name" should take precedence over "template".
	if result.Findings[0].Title != "SQL Injection" {
		t.Errorf("finding.Title = %q, want %q (name should take precedence over template)", result.Findings[0].Title, "SQL Injection")
	}
}

// ---------------------------------------------------------------------------
// Stage execution order
// ---------------------------------------------------------------------------

// capturingOrderAdapter records its label when Run is called to allow tests to
// assert on stage execution order.
type capturingOrderAdapter struct {
	adapter.MockAdapter
	label string
	order *[]string
}

func (c *capturingOrderAdapter) ID() adapter.AdapterID { return c.MockAdapter.MockID }
func (c *capturingOrderAdapter) Name() string          { return c.MockAdapter.MockName }
func (c *capturingOrderAdapter) Check(ctx context.Context) (string, error) {
	return c.MockAdapter.Check(ctx)
}
func (c *capturingOrderAdapter) Run(ctx context.Context, input adapter.AdapterInput, cfg adapter.AdapterConfig, pw io.Writer) (adapter.AdapterOutput, error) {
	*c.order = append(*c.order, c.label)
	return c.MockAdapter.Run(ctx, input, cfg, pw)
}

// TestPipeline_Integration_StagesExecuteInOrder verifies that stages execute
// in the order they are defined.
func TestPipeline_Integration_StagesExecuteInOrder(t *testing.T) {
	var callOrder []string

	a1 := &capturingOrderAdapter{
		MockAdapter: adapter.MockAdapter{MockID: adapter.AdapterIDEmail, MockName: "email"},
		label:       "email",
		order:       &callOrder,
	}
	a2 := &capturingOrderAdapter{
		MockAdapter: adapter.MockAdapter{MockID: adapter.AdapterIDSubfinder, MockName: "subfinder"},
		label:       "subfinder",
		order:       &callOrder,
	}
	a3 := &capturingOrderAdapter{
		MockAdapter: adapter.MockAdapter{MockID: adapter.AdapterIDHTTPX, MockName: "httpx"},
		label:       "httpx",
		order:       &callOrder,
	}

	reg := buildRegistry(a1, a2, a3)
	stages := []pipeline.Stage{
		{Name: "Email", AdapterID: adapter.AdapterIDEmail, Required: false},
		{Name: "Subdomain", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	_, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(callOrder) != 3 {
		t.Fatalf("expected 3 stage executions, got %d: %v", len(callOrder), callOrder)
	}
	expected := []string{"email", "subfinder", "httpx"}
	for i, want := range expected {
		if callOrder[i] != want {
			t.Errorf("execution order[%d] = %q, want %q", i, callOrder[i], want)
		}
	}
}

// ---------------------------------------------------------------------------
// Data feed-forward
// ---------------------------------------------------------------------------

// capturingInputAdapter records the AdapterInput received during Run.
type capturingInputAdapter struct {
	adapter.MockAdapter
	capture *adapter.AdapterInput
}

func (c *capturingInputAdapter) ID() adapter.AdapterID { return c.MockAdapter.MockID }
func (c *capturingInputAdapter) Name() string          { return c.MockAdapter.MockName }
func (c *capturingInputAdapter) Check(ctx context.Context) (string, error) {
	return c.MockAdapter.Check(ctx)
}
func (c *capturingInputAdapter) Run(ctx context.Context, input adapter.AdapterInput, cfg adapter.AdapterConfig, pw io.Writer) (adapter.AdapterOutput, error) {
	if c.capture != nil {
		*c.capture = input
	}
	return c.MockAdapter.Run(ctx, input, cfg, pw)
}

// TestPipeline_Integration_DataFeedForwardFiveStages verifies that data
// discovered in earlier stages propagates to all subsequent stages.
func TestPipeline_Integration_DataFeedForwardFiveStages(t *testing.T) {
	var inputs [5]adapter.AdapterInput

	emailStage := &capturingInputAdapter{
		MockAdapter: adapter.MockAdapter{MockID: adapter.AdapterIDEmail, MockName: "email"},
		capture:     &inputs[0],
	}
	subfinderStage := &capturingInputAdapter{
		MockAdapter: adapter.MockAdapter{
			MockID:         adapter.AdapterIDSubfinder,
			MockName:       "subfinder",
			MockSubdomains: []string{"api.example.com", "mail.example.com"},
		},
		capture: &inputs[1],
	}
	httpxStage := &capturingInputAdapter{
		MockAdapter: adapter.MockAdapter{
			MockID:        adapter.AdapterIDHTTPX,
			MockName:      "httpx",
			MockLiveHosts: []string{"https://api.example.com"},
		},
		capture: &inputs[2],
	}
	naabuStage := &capturingInputAdapter{
		MockAdapter: adapter.MockAdapter{
			MockID:        adapter.AdapterIDNaabu,
			MockName:      "naabu",
			MockOpenPorts: []string{"api.example.com:443"},
		},
		capture: &inputs[3],
	}
	nucleiStage := &capturingInputAdapter{
		MockAdapter: adapter.MockAdapter{
			MockID:   adapter.AdapterIDNuclei,
			MockName: "nuclei",
		},
		capture: &inputs[4],
	}

	reg := buildRegistry(emailStage, subfinderStage, httpxStage, naabuStage, nucleiStage)
	stages := pipeline.DefaultStages()
	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)

	_, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Stage 0 (email): bare domain, no subdomains yet.
	if len(inputs[0].Subdomains) != 0 {
		t.Errorf("stage[email] input has %d subdomains, want 0", len(inputs[0].Subdomains))
	}
	if inputs[0].Domain != "example.com" {
		t.Errorf("stage[email] input domain = %q, want %q", inputs[0].Domain, "example.com")
	}

	// Stage 1 (subfinder): bare domain, no subdomains yet.
	if len(inputs[1].Subdomains) != 0 {
		t.Errorf("stage[subfinder] input has %d subdomains, want 0", len(inputs[1].Subdomains))
	}

	// Stage 2 (httpx): must have subdomains from subfinder.
	if len(inputs[2].Subdomains) != 2 {
		t.Errorf("stage[httpx] input has %d subdomains, want 2: %v", len(inputs[2].Subdomains), inputs[2].Subdomains)
	}

	// Stage 3 (naabu): must have subdomains + live hosts.
	if len(inputs[3].Subdomains) != 2 {
		t.Errorf("stage[naabu] input has %d subdomains, want 2", len(inputs[3].Subdomains))
	}
	if len(inputs[3].LiveHosts) != 1 {
		t.Errorf("stage[naabu] input has %d live hosts, want 1", len(inputs[3].LiveHosts))
	}

	// Stage 4 (nuclei): must have subdomains, live hosts, and open ports.
	if len(inputs[4].Subdomains) != 2 {
		t.Errorf("stage[nuclei] input has %d subdomains, want 2", len(inputs[4].Subdomains))
	}
	if len(inputs[4].LiveHosts) != 1 {
		t.Errorf("stage[nuclei] input has %d live hosts, want 1", len(inputs[4].LiveHosts))
	}
	if len(inputs[4].OpenPorts) != 1 {
		t.Errorf("stage[nuclei] input has %d open ports, want 1", len(inputs[4].OpenPorts))
	}
}

// ---------------------------------------------------------------------------
// Compliance mapping integration
// ---------------------------------------------------------------------------

// TestPipeline_Integration_ComplianceMapping verifies that findings from the
// pipeline can be enriched with compliance mappings after the pipeline run.
func TestPipeline_Integration_ComplianceMapping(t *testing.T) {
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{
				ToolName: "nuclei",
				ToolOutput: map[string]interface{}{
					"host":        "target.example.com",
					"template-id": "log4shell-rce",
					"info": map[string]interface{}{
						"name":     "Log4Shell RCE",
						"severity": "critical",
					},
				},
			},
			{
				ToolName: "nuclei",
				ToolOutput: map[string]interface{}{
					"host":        "target.example.com",
					"template-id": "info-disclosure",
					"info": map[string]interface{}{
						"name":     "Information Disclosure",
						"severity": "info",
					},
				},
			},
		},
	}

	reg := buildRegistry(nucleiAdapter)
	p := pipeline.New(reg, pipeline.PipelineConfig{}, []pipeline.Stage{
		{Name: "Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	})
	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	// Apply compliance mapping post-pipeline.
	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error: %v", err)
	}

	enriched := mapper.MapFindings(result.Findings)
	if len(enriched) != 2 {
		t.Fatalf("MapFindings returned %d findings, want 2", len(enriched))
	}

	// The critical finding (no CWE/CVE) should trigger the severity fallback to 6.3.1.
	criticalFinding := enriched[0]
	foundFallback := false
	for _, m := range criticalFinding.Compliance {
		if m.ControlID == "6.3.1" && m.Framework == "pci-dss-4.0" {
			foundFallback = true
		}
	}
	if !foundFallback {
		t.Errorf("critical finding should have PCI DSS 6.3.1 mapping via severity fallback, got: %v", criticalFinding.Compliance)
	}

	// The info finding should get no compliance mapping.
	infoFinding := enriched[1]
	if len(infoFinding.Compliance) > 0 {
		t.Errorf("info severity finding should have no compliance mappings, got: %v", infoFinding.Compliance)
	}
}

// TestPipeline_Integration_ComplianceMappingWithCWE verifies that findings
// annotated with CWE receive the correct PCI DSS control mappings.
func TestPipeline_Integration_ComplianceMappingWithCWE(t *testing.T) {
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{
				ToolName: "nuclei",
				ToolOutput: map[string]interface{}{
					"host":        "target.example.com",
					"template-id": "xss-generic",
					"info": map[string]interface{}{
						"name":     "XSS Vulnerability",
						"severity": "high",
					},
				},
			},
		},
	}

	reg := buildRegistry(nucleiAdapter)
	p := pipeline.New(reg, pipeline.PipelineConfig{}, []pipeline.Stage{
		{Name: "Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	})
	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually annotate finding with CWE (simulating enrichment from another source).
	findings := result.Findings
	findings[0].CWE = "CWE-79"

	mapper, err := compliance.NewPCIDSSMapper()
	if err != nil {
		t.Fatalf("NewPCIDSSMapper() error: %v", err)
	}
	enriched := mapper.MapFindings(findings)

	// CWE-79 (XSS) should map to 6.2.4 and 6.4.1.
	cweFound624 := false
	cweFound641 := false
	for _, m := range enriched[0].Compliance {
		if m.ControlID == "6.2.4" {
			cweFound624 = true
		}
		if m.ControlID == "6.4.1" {
			cweFound641 = true
		}
	}
	if !cweFound624 {
		t.Error("CWE-79 should produce PCI DSS 6.2.4 mapping")
	}
	if !cweFound641 {
		t.Error("CWE-79 should produce PCI DSS 6.4.1 mapping")
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

// TestPipeline_Integration_DeduplicatedSubdomains verifies that duplicate
// subdomains reported by a stage are deduplicated before being passed forward.
func TestPipeline_Integration_DeduplicatedSubdomains(t *testing.T) {
	var httpxInput adapter.AdapterInput

	s1 := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"api.example.com", "www.example.com", "api.example.com"}, // intentional duplicate
	}
	s2 := &capturingInputAdapter{
		MockAdapter: adapter.MockAdapter{
			MockID:        adapter.AdapterIDHTTPX,
			MockName:      "httpx",
			MockLiveHosts: []string{"https://api.example.com"},
		},
		capture: &httpxInput,
	}

	reg := buildRegistry(s1, s2)
	stages := []pipeline.Stage{
		{Name: "Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	_, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// httpx should receive exactly 2 unique subdomains.
	if len(httpxInput.Subdomains) != 2 {
		t.Errorf("expected 2 deduplicated subdomains, got %d: %v", len(httpxInput.Subdomains), httpxInput.Subdomains)
	}
}

// TestPipeline_Integration_PartialFailure_OptionalStagesSkipped verifies that
// optional stage failures do not prevent subsequent stages from running.
func TestPipeline_Integration_PartialFailure_OptionalStagesSkipped(t *testing.T) {
	errNaabu := errors.New("naabu: port scan timeout")

	subfinderAdapter := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"api.example.com"},
	}
	httpxAdapter := &adapter.MockAdapter{
		MockID:        adapter.AdapterIDHTTPX,
		MockName:      "httpx",
		MockLiveHosts: []string{"https://api.example.com"},
	}
	naabuAdapter := &adapter.MockAdapter{
		MockID:    adapter.AdapterIDNaabu,
		MockName:  "naabu",
		MockError: errNaabu,
	}
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{ToolName: "nuclei", ToolOutput: map[string]interface{}{"host": "api.example.com", "name": "XSS", "severity": "high"}},
		},
	}

	reg := buildRegistry(subfinderAdapter, httpxAdapter, naabuAdapter, nucleiAdapter)
	stages := []pipeline.Stage{
		{Name: "Subdomain Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "HTTP Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
		{Name: "Port Scanning", AdapterID: adapter.AdapterIDNaabu, Required: false}, // optional — fails
		{Name: "Vulnerability Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	result, err := p.Run(context.Background(), "example.com", nil)

	// No fatal error — naabu is optional.
	if err != nil {
		t.Fatalf("optional stage failure should not stop pipeline, got: %v", err)
	}

	// All 4 stage results present.
	if len(result.Stages) != 4 {
		t.Fatalf("expected 4 stage results, got %d", len(result.Stages))
	}

	// Naabu stage should be marked failed.
	naabuResult := result.Stages[2]
	if naabuResult.Status != "failed" {
		t.Errorf("naabu stage status = %q, want %q", naabuResult.Status, "failed")
	}
	if !errors.Is(naabuResult.Error, errNaabu) {
		t.Errorf("naabu stage error = %v, want wrapping %v", naabuResult.Error, errNaabu)
	}

	// Nuclei findings should still be collected.
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding from nuclei, got %d", len(result.Findings))
	}
}

// TestPipeline_Integration_NilProgressWriter verifies the pipeline does not
// panic when progressWriter is nil.
func TestPipeline_Integration_NilProgressWriter(t *testing.T) {
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
	}
	reg := buildRegistry(nucleiAdapter)
	stages := []pipeline.Stage{
		{Name: "Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	}
	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("pipeline panicked with nil progressWriter: %v", r)
		}
	}()

	_, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPipeline_Integration_EmptyDomain verifies the pipeline handles an empty
// domain string without panicking (the domain is propagated as-is).
func TestPipeline_Integration_EmptyDomain(t *testing.T) {
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
	}
	reg := buildRegistry(nucleiAdapter)
	stages := []pipeline.Stage{
		{Name: "Scan", AdapterID: adapter.AdapterIDNuclei, Required: false},
	}
	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("pipeline panicked with empty domain: %v", r)
		}
	}()

	result, err := p.Run(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Domain != "" {
		t.Errorf("result.Domain = %q, want empty string", result.Domain)
	}
}

// TestPipeline_Integration_StageStatsPopulated verifies that stage statistics
// are populated correctly with counts from each stage's output.
func TestPipeline_Integration_StageStatsPopulated(t *testing.T) {
	subfinderAdapter := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"a.example.com", "b.example.com", "c.example.com"},
	}
	httpxAdapter := &adapter.MockAdapter{
		MockID:        adapter.AdapterIDHTTPX,
		MockName:      "httpx",
		MockLiveHosts: []string{"https://a.example.com", "https://b.example.com"},
	}

	reg := buildRegistry(subfinderAdapter, httpxAdapter)
	stages := []pipeline.Stage{
		{Name: "Subdomain Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "HTTP Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
	}
	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	subfinderStats := result.Stages[0].Stats
	if subfinderStats["subdomains"] != 3 {
		t.Errorf("subfinder stage stats subdomains = %d, want 3", subfinderStats["subdomains"])
	}
	if subfinderStats["live_hosts"] != 0 {
		t.Errorf("subfinder stage stats live_hosts = %d, want 0", subfinderStats["live_hosts"])
	}

	httpxStats := result.Stages[1].Stats
	if httpxStats["live_hosts"] != 2 {
		t.Errorf("httpx stage stats live_hosts = %d, want 2", httpxStats["live_hosts"])
	}
}

// TestPipeline_Integration_FindingNilToolOutput verifies that a finding with
// a nil ToolOutput doesn't panic and produces a finding with default fields.
func TestPipeline_Integration_FindingNilToolOutput(t *testing.T) {
	nucleiAdapter := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{
				ToolName:   "nuclei",
				ToolOutput: nil, // nil tool output
			},
		},
	}

	reg := buildRegistry(nucleiAdapter)
	p := pipeline.New(reg, pipeline.PipelineConfig{}, []pipeline.Stage{
		{Name: "Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	})

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("pipeline panicked with nil ToolOutput: %v", r)
		}
	}()

	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	f := result.Findings[0]
	if f.Tool != "nuclei" {
		t.Errorf("finding.Tool = %q, want %q", f.Tool, "nuclei")
	}
	// Severity should default to SeverityInfo when not specified.
	if f.Severity != finding.SeverityInfo {
		t.Errorf("finding.Severity = %v, want %v (default)", f.Severity, finding.SeverityInfo)
	}
}
