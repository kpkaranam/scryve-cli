// Package pipeline_test — rate-limit propagation tests.
//
// These tests verify that:
//   - When PipelineConfig.RateLimit is 0 (unset), the pipeline uses a default
//     of 50 req/s for every adapter.
//   - When PipelineConfig.RateLimit is set explicitly, that value is forwarded
//     to every adapter's AdapterConfig.RateLimit.
//   - A rate-limit of 0 from the caller (meaning "use default") results in
//     adapters receiving DefaultRateLimit (50), not 0.
package pipeline_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/pipeline"
)

// rateLimitCapture is a MockAdapter that records the AdapterConfig it receives
// so tests can assert on the RateLimit value seen by the adapter.
type rateLimitCapture struct {
	adapter.MockAdapter
	capturedCfg *adapter.AdapterConfig
}

func (r *rateLimitCapture) ID() adapter.AdapterID { return r.MockAdapter.MockID }
func (r *rateLimitCapture) Name() string          { return r.MockAdapter.MockName }
func (r *rateLimitCapture) Check(ctx context.Context) (string, error) {
	return r.MockAdapter.Check(ctx)
}
func (r *rateLimitCapture) Run(ctx context.Context, input adapter.AdapterInput, cfg adapter.AdapterConfig, pw io.Writer) (adapter.AdapterOutput, error) {
	if r.capturedCfg != nil {
		*r.capturedCfg = cfg
	}
	return r.MockAdapter.Run(ctx, input, cfg, pw)
}

// ---------------------------------------------------------------------------
// TestPipeline_DefaultRateLimit — when PipelineConfig.RateLimit is 0 (unset),
// adapters must receive pipeline.DefaultRateLimit (50).
// ---------------------------------------------------------------------------

func TestPipeline_DefaultRateLimit(t *testing.T) {
	var capturedCfg adapter.AdapterConfig

	a := &rateLimitCapture{
		MockAdapter: adapter.MockAdapter{
			MockID:   adapter.AdapterIDSubfinder,
			MockName: "subfinder",
		},
		capturedCfg: &capturedCfg,
	}

	reg := buildRegistry(a)
	stages := []pipeline.Stage{
		{Name: "Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
	}

	// RateLimit is explicitly 0 — the pipeline must apply the default.
	cfg := pipeline.PipelineConfig{
		RateLimit: 0,
		Timeout:   5 * time.Second,
	}

	p := pipeline.New(reg, cfg, stages)
	_, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if capturedCfg.RateLimit != pipeline.DefaultRateLimit {
		t.Errorf("adapter received RateLimit = %d, want DefaultRateLimit (%d)",
			capturedCfg.RateLimit, pipeline.DefaultRateLimit)
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_ExplicitRateLimit — when PipelineConfig.RateLimit is set to a
// positive value, every adapter must receive that exact value.
// ---------------------------------------------------------------------------

func TestPipeline_ExplicitRateLimit(t *testing.T) {
	const wantRate = 100

	var cfgA, cfgB adapter.AdapterConfig

	a1 := &rateLimitCapture{
		MockAdapter: adapter.MockAdapter{
			MockID:         adapter.AdapterIDSubfinder,
			MockName:       "subfinder",
			MockSubdomains: []string{"api.example.com"},
		},
		capturedCfg: &cfgA,
	}
	a2 := &rateLimitCapture{
		MockAdapter: adapter.MockAdapter{
			MockID:        adapter.AdapterIDHTTPX,
			MockName:      "httpx",
			MockLiveHosts: []string{"https://api.example.com"},
		},
		capturedCfg: &cfgB,
	}

	reg := buildRegistry(a1, a2)
	stages := []pipeline.Stage{
		{Name: "Discovery", AdapterID: adapter.AdapterIDSubfinder, Required: true},
		{Name: "Probing", AdapterID: adapter.AdapterIDHTTPX, Required: true},
	}

	cfg := pipeline.PipelineConfig{
		RateLimit: wantRate,
		Timeout:   5 * time.Second,
	}

	p := pipeline.New(reg, cfg, stages)
	_, err := p.Run(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if cfgA.RateLimit != wantRate {
		t.Errorf("stage 1 adapter received RateLimit = %d, want %d", cfgA.RateLimit, wantRate)
	}
	if cfgB.RateLimit != wantRate {
		t.Errorf("stage 2 adapter received RateLimit = %d, want %d", cfgB.RateLimit, wantRate)
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_DefaultRateLimitConstant — DefaultRateLimit exported constant
// has the documented value of 50.
// ---------------------------------------------------------------------------

func TestPipeline_DefaultRateLimitConstant(t *testing.T) {
	if pipeline.DefaultRateLimit != 50 {
		t.Errorf("pipeline.DefaultRateLimit = %d, want 50", pipeline.DefaultRateLimit)
	}
}
