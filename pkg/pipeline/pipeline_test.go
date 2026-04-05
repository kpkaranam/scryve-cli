// Package pipeline_test contains black-box tests for the pipeline orchestrator.
package pipeline_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/pipeline"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildRegistry creates a fresh registry and registers the provided adapters.
func buildRegistry(adapters ...adapter.Adapter) *adapter.Registry {
	reg := adapter.NewRegistry()
	for _, a := range adapters {
		reg.Register(a)
	}
	return reg
}

// ---------------------------------------------------------------------------
// TestPipeline_EmptyStages — empty stage list returns an empty result with no
// error.
// ---------------------------------------------------------------------------

func TestPipeline_EmptyStages(t *testing.T) {
	reg := buildRegistry()
	cfg := pipeline.PipelineConfig{Timeout: 5 * time.Second}

	p := pipeline.New(reg, cfg, nil) // no stages
	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("Run with no stages returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Run returned nil result")
	}
	if result.Domain != "example.com" {
		t.Errorf("result.Domain = %q, want %q", result.Domain, "example.com")
	}
	if len(result.Stages) != 0 {
		t.Errorf("expected 0 stage results, got %d", len(result.Stages))
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_FullRun — three mock stages run successfully in order.
// ---------------------------------------------------------------------------

func TestPipeline_FullRun(t *testing.T) {
	discovery := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"api.example.com", "www.example.com"},
	}
	probe := &adapter.MockAdapter{
		MockID:        adapter.AdapterIDHTTPX,
		MockName:      "httpx",
		MockLiveHosts: []string{"https://api.example.com", "https://www.example.com"},
	}
	scan := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
		MockFindings: []adapter.RawFinding{
			{ToolName: "nuclei", ToolOutput: map[string]interface{}{"template": "cve-2021-44228", "host": "api.example.com"}},
		},
	}

	reg := buildRegistry(discovery, probe, scan)
	stages := []pipeline.Stage{
		{Name: "Subdomain Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "HTTP Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
		{Name: "Vulnerability Scan", AdapterID: adapter.AdapterIDNuclei, Required: true},
	}

	cfg := pipeline.PipelineConfig{Timeout: 5 * time.Second}
	p := pipeline.New(reg, cfg, stages)

	var buf bytes.Buffer
	result, err := p.Run(context.Background(), "example.com", &buf)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if len(result.Stages) != 3 {
		t.Fatalf("expected 3 stage results, got %d", len(result.Stages))
	}

	for i, sr := range result.Stages {
		if sr.Status != "completed" {
			t.Errorf("stage[%d] %q status = %q, want %q", i, sr.Stage.Name, sr.Status, "completed")
		}
		if sr.Error != nil {
			t.Errorf("stage[%d] %q unexpected error: %v", i, sr.Stage.Name, sr.Error)
		}
	}

	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Error != nil {
		t.Errorf("result.Error should be nil, got: %v", result.Error)
	}
	if result.CompletedAt.IsZero() {
		t.Error("result.CompletedAt should not be zero")
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_DataFeedForward — subdomains from stage 1 are passed into
// stage 2's input; live hosts from stage 2 are passed into stage 3.
// ---------------------------------------------------------------------------

// capturingMock is a MockAdapter variant that records the AdapterInput it
// receives during Run so tests can assert on data feed-forward behavior.
type capturingMock struct {
	adapter.MockAdapter
	capture *adapter.AdapterInput
}

// ID, Name, Check delegate to the embedded MockAdapter.
func (c *capturingMock) ID() adapter.AdapterID { return c.MockAdapter.MockID }
func (c *capturingMock) Name() string          { return c.MockAdapter.MockName }
func (c *capturingMock) Check(ctx context.Context) (string, error) {
	return c.MockAdapter.Check(ctx)
}

// Run records the input then delegates to MockAdapter.Run.
func (c *capturingMock) Run(ctx context.Context, input adapter.AdapterInput, cfg adapter.AdapterConfig, pw io.Writer) (adapter.AdapterOutput, error) {
	if c.capture != nil {
		*c.capture = input
	}
	return c.MockAdapter.Run(ctx, input, cfg, pw)
}

func TestPipeline_DataFeedForward(t *testing.T) {
	var capturedInputs [3]adapter.AdapterInput

	// Stage 1: produces subdomains.
	s1 := &capturingMock{
		MockAdapter: adapter.MockAdapter{
			MockID:         adapter.AdapterIDSubfinder,
			MockName:       "subfinder",
			MockSubdomains: []string{"api.example.com", "mail.example.com"},
		},
		capture: &capturedInputs[0],
	}

	// Stage 2: consumes subdomains, produces live hosts.
	s2 := &capturingMock{
		MockAdapter: adapter.MockAdapter{
			MockID:        adapter.AdapterIDHTTPX,
			MockName:      "httpx",
			MockLiveHosts: []string{"https://api.example.com"},
		},
		capture: &capturedInputs[1],
	}

	// Stage 3: consumes live hosts and subdomains.
	s3 := &capturingMock{
		MockAdapter: adapter.MockAdapter{
			MockID:   adapter.AdapterIDNuclei,
			MockName: "nuclei",
		},
		capture: &capturedInputs[2],
	}

	reg := buildRegistry(s1, s2, s3)
	stages := []pipeline.Stage{
		{Name: "Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
		{Name: "Scanning", AdapterID: adapter.AdapterIDNuclei, Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{Timeout: 5 * time.Second}, stages)
	_, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	// Stage 1 receives bare domain, no subdomains yet.
	if len(capturedInputs[0].Subdomains) != 0 {
		t.Errorf("stage1 input: expected 0 subdomains, got %v", capturedInputs[0].Subdomains)
	}

	// Stage 2 must receive subdomains from stage 1.
	if len(capturedInputs[1].Subdomains) != 2 {
		t.Errorf("stage2 input: expected 2 subdomains, got %v", capturedInputs[1].Subdomains)
	}

	// Stage 3 must receive live hosts from stage 2.
	if len(capturedInputs[2].LiveHosts) != 1 {
		t.Errorf("stage3 input: expected 1 live host, got %v", capturedInputs[2].LiveHosts)
	}
	// Stage 3 must also inherit accumulated subdomains.
	if len(capturedInputs[2].Subdomains) != 2 {
		t.Errorf("stage3 input: expected 2 subdomains (accumulated), got %v", capturedInputs[2].Subdomains)
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_RequiredStageFailure — a required stage failure stops pipeline.
// ---------------------------------------------------------------------------

func TestPipeline_RequiredStageFailure(t *testing.T) {
	errBoom := errors.New("required stage exploded")

	s1 := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"api.example.com"},
	}
	s2 := &adapter.MockAdapter{
		MockID:    adapter.AdapterIDHTTPX,
		MockName:  "httpx",
		MockError: errBoom,
	}
	// s3 should never run.
	s3 := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDNuclei,
		MockName: "nuclei",
	}

	reg := buildRegistry(s1, s2, s3)
	stages := []pipeline.Stage{
		{Name: "Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},    // fails
		{Name: "Scanning", AdapterID: adapter.AdapterIDNuclei, Required: false}, // must not run
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{Timeout: 5 * time.Second}, stages)
	result, err := p.Run(context.Background(), "example.com", nil)

	// Run must return a non-nil error.
	if err == nil {
		t.Fatal("expected error from required stage failure, got nil")
	}

	if result == nil {
		t.Fatal("result must not be nil even on failure")
	}

	// Only 2 stage results: discovery (ok) + probing (failed). Scanning skipped.
	if len(result.Stages) != 2 {
		t.Errorf("expected 2 stage results, got %d", len(result.Stages))
	}

	failed := result.Stages[1]
	if failed.Status != "failed" {
		t.Errorf("failed stage status = %q, want %q", failed.Status, "failed")
	}
	if !errors.Is(failed.Error, errBoom) {
		t.Errorf("failed stage error = %v, want wrapping %v", failed.Error, errBoom)
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_OptionalStageFailure — optional stage failure continues the
// pipeline.
// ---------------------------------------------------------------------------

func TestPipeline_OptionalStageFailure(t *testing.T) {
	errOptional := errors.New("optional stage failed")

	s1 := &adapter.MockAdapter{
		MockID:    adapter.AdapterIDNaabu,
		MockName:  "naabu",
		MockError: errOptional,
	}
	s2 := &adapter.MockAdapter{
		MockID:        adapter.AdapterIDHTTPX,
		MockName:      "httpx",
		MockLiveHosts: []string{"https://example.com"},
	}

	reg := buildRegistry(s1, s2)
	stages := []pipeline.Stage{
		{Name: "Port Scan", AdapterID: adapter.AdapterIDNaabu, Required: false}, // optional — fails
		{Name: "Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},    // must still run
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{Timeout: 5 * time.Second}, stages)
	result, err := p.Run(context.Background(), "example.com", nil)

	// No top-level error.
	if err != nil {
		t.Fatalf("optional failure should not return top-level error, got: %v", err)
	}

	if len(result.Stages) != 2 {
		t.Fatalf("expected 2 stage results, got %d", len(result.Stages))
	}

	if result.Stages[0].Status != "failed" {
		t.Errorf("optional stage status = %q, want %q", result.Stages[0].Status, "failed")
	}
	if result.Stages[1].Status != "completed" {
		t.Errorf("subsequent stage status = %q, want %q", result.Stages[1].Status, "completed")
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_ContextCancellation — canceling the context stops the pipeline.
// ---------------------------------------------------------------------------

func TestPipeline_ContextCancellation(t *testing.T) {
	s1 := &adapter.MockAdapter{
		MockID:    adapter.AdapterIDSubfinder,
		MockName:  "subfinder",
		MockDelay: 200 * time.Millisecond,
	}
	s2 := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDHTTPX,
		MockName: "httpx",
	}

	reg := buildRegistry(s1, s2)
	stages := []pipeline.Stage{
		{Name: "Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	p := pipeline.New(reg, pipeline.PipelineConfig{Timeout: 5 * time.Second}, stages)
	result, err := p.Run(ctx, "example.com", nil)

	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("expected context error, got: %v", err)
	}
	if result == nil {
		t.Fatal("result must not be nil on context cancellation")
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_AdapterNotRegistered_Required — required stage with unknown
// adapter ID fails the pipeline.
// ---------------------------------------------------------------------------

func TestPipeline_AdapterNotRegistered_Required(t *testing.T) {
	reg := buildRegistry() // empty registry
	stages := []pipeline.Stage{
		{Name: "Ghost Stage", AdapterID: adapter.AdapterID("ghost"), Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{Timeout: 5 * time.Second}, stages)
	result, err := p.Run(context.Background(), "example.com", nil)
	if err == nil {
		t.Fatal("expected error when required adapter not found, got nil")
	}
	if result == nil {
		t.Fatal("result must not be nil")
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_AdapterNotRegistered_Optional — optional stage with unknown
// adapter ID is skipped and pipeline continues.
// ---------------------------------------------------------------------------

func TestPipeline_AdapterNotRegistered_Optional(t *testing.T) {
	s2 := &adapter.MockAdapter{
		MockID:        adapter.AdapterIDHTTPX,
		MockName:      "httpx",
		MockLiveHosts: []string{"https://example.com"},
	}
	reg := buildRegistry(s2)
	stages := []pipeline.Stage{
		{Name: "Ghost Stage", AdapterID: adapter.AdapterID("ghost"), Required: false},
		{Name: "Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{Timeout: 5 * time.Second}, stages)
	result, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("optional missing adapter should not stop pipeline, got: %v", err)
	}
	if len(result.Stages) != 2 {
		t.Fatalf("expected 2 stage results, got %d", len(result.Stages))
	}
	if result.Stages[0].Status != "skipped" {
		t.Errorf("ghost stage status = %q, want %q", result.Stages[0].Status, "skipped")
	}
	if result.Stages[1].Status != "completed" {
		t.Errorf("http probing status = %q, want %q", result.Stages[1].Status, "completed")
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_TimingFields — StartedAt and CompletedAt are populated.
// ---------------------------------------------------------------------------

func TestPipeline_TimingFields(t *testing.T) {
	s1 := &adapter.MockAdapter{
		MockID:   adapter.AdapterIDSubfinder,
		MockName: "subfinder",
	}
	reg := buildRegistry(s1)
	stages := []pipeline.Stage{
		{Name: "Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
	}

	before := time.Now()
	p := pipeline.New(reg, pipeline.PipelineConfig{Timeout: 5 * time.Second}, stages)
	result, err := p.Run(context.Background(), "example.com", nil)
	after := time.Now()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StartedAt.Before(before) || result.StartedAt.After(after) {
		t.Errorf("StartedAt %v outside expected window [%v, %v]", result.StartedAt, before, after)
	}
	if result.CompletedAt.Before(result.StartedAt) {
		t.Errorf("CompletedAt %v is before StartedAt %v", result.CompletedAt, result.StartedAt)
	}
}

// ---------------------------------------------------------------------------
// TestDefaultStages — verifies the default stage list contains required adapters.
// ---------------------------------------------------------------------------

func TestDefaultStages(t *testing.T) {
	stages := pipeline.DefaultStages()
	if len(stages) == 0 {
		t.Fatal("DefaultStages returned empty slice")
	}

	required := map[adapter.AdapterID]bool{
		adapter.AdapterIDSubfinder: false,
		adapter.AdapterIDHTTPX:     false,
		adapter.AdapterIDNuclei:    false,
	}
	for _, s := range stages {
		if _, ok := required[s.AdapterID]; ok {
			required[s.AdapterID] = true
		}
	}
	for id, found := range required {
		if !found {
			t.Errorf("required adapter %q missing from DefaultStages", id)
		}
	}
}
