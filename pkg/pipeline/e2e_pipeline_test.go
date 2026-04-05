// E2E tests for pipeline orchestration — Story 3.1
package pipeline_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/pipeline"
)

func TestE2E_Pipeline_AllStagesPass(t *testing.T) {
	reg := adapter.NewRegistry()

	// Register mock adapters for 3 stages
	reg.Register(&adapter.MockAdapter{MockID: "mock-sub", MockName: "Subdomain", MockSubdomains: []string{"a.example.com", "b.example.com"}})
	reg.Register(&adapter.MockAdapter{MockID: "mock-httpx", MockName: "HTTPX", MockLiveHosts: []string{"https://a.example.com"}})
	reg.Register(&adapter.MockAdapter{MockID: "mock-nuclei", MockName: "Nuclei", MockFindings: []adapter.RawFinding{
		{ToolName: "nuclei", ToolOutput: map[string]interface{}{"name": "test-vuln", "severity": "high", "host": "a.example.com"}},
	}})

	stages := []pipeline.Stage{
		{Name: "Subdomain", AdapterID: "mock-sub", Required: true},
		{Name: "HTTPX", AdapterID: "mock-httpx", Required: true},
		{Name: "Nuclei", AdapterID: "mock-nuclei", Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{RateLimit: 50}, stages)
	result, err := p.Run(context.Background(), "example.com", &bytes.Buffer{})

	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}
	if len(result.Stages) != 3 {
		t.Errorf("expected 3 stages, got %d", len(result.Stages))
	}
	for _, sr := range result.Stages {
		if sr.Status != "completed" {
			t.Errorf("stage %q status = %q, want completed", sr.Stage.Name, sr.Status)
		}
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings from nuclei stage")
	}
}

func TestE2E_Pipeline_RequiredStageFailure(t *testing.T) {
	reg := adapter.NewRegistry()
	reg.Register(&adapter.MockAdapter{MockID: "mock-fail", MockName: "Fail", MockError: fmt.Errorf("simulated adapter failure")})
	reg.Register(&adapter.MockAdapter{MockID: "mock-ok", MockName: "OK"})

	stages := []pipeline.Stage{
		{Name: "Fail", AdapterID: "mock-fail", Required: true},
		{Name: "OK", AdapterID: "mock-ok", Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	result, err := p.Run(context.Background(), "example.com", &bytes.Buffer{})

	if err == nil {
		t.Fatal("expected error from required stage failure")
	}
	// Second stage should not have run
	if len(result.Stages) > 1 {
		for _, sr := range result.Stages[1:] {
			if sr.Status == "completed" {
				t.Error("stages after failed required stage should not complete")
			}
		}
	}
}

func TestE2E_Pipeline_OptionalStageFailure(t *testing.T) {
	reg := adapter.NewRegistry()
	reg.Register(&adapter.MockAdapter{MockID: "mock-fail", MockName: "OptFail", MockError: fmt.Errorf("simulated optional failure")})
	reg.Register(&adapter.MockAdapter{MockID: "mock-ok", MockName: "OK"})

	stages := []pipeline.Stage{
		{Name: "OptFail", AdapterID: "mock-fail", Required: false},
		{Name: "OK", AdapterID: "mock-ok", Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	result, err := p.Run(context.Background(), "example.com", &bytes.Buffer{})

	if err != nil {
		t.Fatalf("optional failure should not abort pipeline: %v", err)
	}
	if len(result.Stages) != 2 {
		t.Errorf("expected 2 stages, got %d", len(result.Stages))
	}
}

func TestE2E_Pipeline_ContextCancellation(t *testing.T) {
	reg := adapter.NewRegistry()
	reg.Register(&adapter.MockAdapter{MockID: "mock-slow", MockName: "Slow"})
	reg.Register(&adapter.MockAdapter{MockID: "mock-after", MockName: "After"})

	stages := []pipeline.Stage{
		{Name: "Slow", AdapterID: "mock-slow", Required: true},
		{Name: "After", AdapterID: "mock-after", Required: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	result, err := p.Run(ctx, "example.com", &bytes.Buffer{})

	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if result == nil {
		t.Fatal("result should not be nil even on cancellation")
	}
}

func TestE2E_Pipeline_EmptyStages(t *testing.T) {
	reg := adapter.NewRegistry()
	p := pipeline.New(reg, pipeline.PipelineConfig{}, nil)

	result, err := p.Run(context.Background(), "example.com", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("empty pipeline should succeed: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("empty pipeline should have 0 findings, got %d", len(result.Findings))
	}
	if result.Domain != "example.com" {
		t.Errorf("domain = %q, want example.com", result.Domain)
	}
}

func TestE2E_Pipeline_DataFlow(t *testing.T) {
	reg := adapter.NewRegistry()

	// Subfinder returns subdomains
	reg.Register(&adapter.MockAdapter{
		MockID: "mock-sub", MockName: "Sub",
		MockSubdomains: []string{"a.example.com", "b.example.com"},
	})
	// HTTPX returns live hosts
	reg.Register(&adapter.MockAdapter{
		MockID: "mock-httpx", MockName: "HTTPX",
		MockLiveHosts: []string{"https://a.example.com"},
	})

	stages := []pipeline.Stage{
		{Name: "Sub", AdapterID: "mock-sub", Required: true},
		{Name: "HTTPX", AdapterID: "mock-httpx", Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{RateLimit: 50}, stages)
	result, err := p.Run(context.Background(), "example.com", &bytes.Buffer{})

	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}
	if len(result.Stages) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(result.Stages))
	}
	// Both stages should complete
	for _, sr := range result.Stages {
		if sr.Status != "completed" {
			t.Errorf("stage %q: status = %q, want completed", sr.Stage.Name, sr.Status)
		}
	}
}

func TestE2E_Pipeline_AdapterNotFound(t *testing.T) {
	reg := adapter.NewRegistry()
	// Don't register anything

	stages := []pipeline.Stage{
		{Name: "Missing", AdapterID: "nonexistent", Required: true},
	}

	p := pipeline.New(reg, pipeline.PipelineConfig{}, stages)
	_, err := p.Run(context.Background(), "example.com", &bytes.Buffer{})

	if err == nil {
		t.Fatal("expected error for missing adapter")
	}
}

func TestE2E_Pipeline_ResultTiming(t *testing.T) {
	reg := adapter.NewRegistry()
	p := pipeline.New(reg, pipeline.PipelineConfig{}, nil)

	before := time.Now()
	result, _ := p.Run(context.Background(), "example.com", nil)
	after := time.Now()

	if result.StartedAt.Before(before) || result.StartedAt.After(after) {
		t.Error("StartedAt should be within test execution window")
	}
	if result.CompletedAt.Before(result.StartedAt) {
		t.Error("CompletedAt should be after StartedAt")
	}
}
