package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/finding"
)

// DefaultRateLimit is the number of requests per second applied to every
// adapter when PipelineConfig.RateLimit is 0 (unset by the caller).
// It is conservative enough to avoid triggering rate-limiting on most targets
// while still completing a typical scan in reasonable time.
const DefaultRateLimit = 50

// PipelineConfig carries runtime settings that apply to every stage in the
// pipeline.  Individual adapter configurations are derived from these values.
type PipelineConfig struct {
	// RateLimit is the maximum number of requests per second passed to each
	// adapter.  0 means use DefaultRateLimit (50 req/s).
	RateLimit int

	// Timeout is the wall-clock time budget for the entire pipeline execution.
	// 0 means no pipeline-level timeout (individual adapter timeouts still
	// apply if configured separately).
	Timeout time.Duration

	// OutputDir is the directory where adapters may write intermediate
	// artifacts (e.g. JSON output files).
	OutputDir string

	// Verbose enables detailed progress logging to the progress writer.
	Verbose bool
}

// PipelineResult is the complete result of a pipeline run.
type PipelineResult struct {
	// Domain is the root domain that was scanned.
	Domain string

	// Stages holds one StageResult per stage that was attempted.
	Stages []StageResult

	// Findings is the flat list of normalised findings collected from all
	// stages.
	Findings []finding.Finding

	// StartedAt is when Run was called.
	StartedAt time.Time

	// CompletedAt is when Run returned (whether successfully or not).
	CompletedAt time.Time

	// Error holds the first fatal error encountered, or nil on success.
	Error error
}

// StageResult captures the outcome of a single pipeline stage.
type StageResult struct {
	// Stage is the definition that was executed.
	Stage Stage

	// Status is one of "completed", "failed", or "skipped".
	Status string

	// Duration is the wall-clock time the stage consumed.
	Duration time.Duration

	// Error is non-nil when Status is "failed".
	Error error

	// Stats holds optional counters emitted by the stage (e.g. {"subdomains": 42}).
	Stats map[string]int
}

// Pipeline is the sequential stage orchestrator.  Create one with New, then
// call Run for each domain you want to scan.
type Pipeline struct {
	stages   []Stage
	registry *adapter.Registry
	config   PipelineConfig
}

// New constructs a Pipeline with the given registry, config, and stage list.
// Pass nil (or an empty slice) for stages to create a no-op pipeline; call
// DefaultStages() for the standard recon sequence.
func New(registry *adapter.Registry, config PipelineConfig, stages []Stage) *Pipeline {
	s := make([]Stage, len(stages))
	copy(s, stages)
	return &Pipeline{
		stages:   s,
		registry: registry,
		config:   config,
	}
}

// Run executes the pipeline stages in order against domain.
//
// Execution rules:
//   - Data (subdomains, live hosts, open ports) discovered by each stage is
//     accumulated in a shared AdapterInput that is passed to every subsequent
//     stage (feed-forward).
//   - Raw findings from every stage are normalised into finding.Finding values
//     and collected in the returned PipelineResult.
//   - If a required stage fails, the pipeline stops and returns a non-nil error.
//   - If an optional stage fails, a warning is written to progressWriter (if
//     non-nil) and the pipeline continues.
//   - Context cancellation is respected between stages and propagated to each
//     adapter's Run call.
//
// Run always returns a non-nil *PipelineResult even on error so callers can
// inspect partial results.
func (p *Pipeline) Run(ctx context.Context, domain string, progressWriter io.Writer) (*PipelineResult, error) {
	result := &PipelineResult{
		Domain:    domain,
		StartedAt: time.Now(),
	}

	// Shared input state that accumulates discovered data across stages.
	accumulated := adapter.AdapterInput{
		Domain: domain,
	}

	// Per-adapter configuration derived from the pipeline-level settings.
	// Apply DefaultRateLimit when the caller did not provide an explicit value.
	adapterCfg := adapter.AdapterConfig{
		RateLimit: effectiveRateLimit(p.config.RateLimit),
		Timeout:   p.config.Timeout,
		OutputDir: p.config.OutputDir,
	}

	var firstFatalErr error

	for i := range p.stages {
		stage := p.stages[i]

		// Respect context cancellation between stages.
		if err := ctx.Err(); err != nil {
			result.Error = err
			result.CompletedAt = time.Now()
			return result, err
		}

		sr, stageErr := p.runStage(ctx, stage, accumulated, adapterCfg, progressWriter)
		result.Stages = append(result.Stages, sr.StageResult)

		if stageErr != nil {
			if stage.Required {
				// Fatal: record the error, stop the pipeline.
				firstFatalErr = fmt.Errorf("required stage %q failed: %w", stage.Name, stageErr)
				result.Error = firstFatalErr
				result.CompletedAt = time.Now()
				return result, firstFatalErr
			}
			// Optional: log warning and continue.
			logProgress(progressWriter, fmt.Sprintf("[pipeline] WARNING: optional stage %q failed: %v — continuing\n", stage.Name, stageErr))
			continue
		}

		// Merge this stage's output into the accumulated input for the next stage.
		accumulated = mergeOutput(accumulated, sr)

		// Collect normalised findings from this stage's raw output.
		result.Findings = append(result.Findings, sr.rawFindings...)
	}

	result.CompletedAt = time.Now()
	return result, nil
}

// runStage executes a single stage and returns its StageResult.
// The raw findings are attached to the stageResultWithFindings wrapper so Run
// can collect them without polluting the public StageResult type.
func (p *Pipeline) runStage(
	ctx context.Context,
	stage Stage,
	input adapter.AdapterInput,
	cfg adapter.AdapterConfig,
	progressWriter io.Writer,
) (stageResultWithFindings, error) {
	sr := stageResultWithFindings{StageResult: StageResult{Stage: stage}}

	// Look up the adapter from the registry.
	a, err := p.registry.Get(stage.AdapterID)
	if err != nil {
		if errors.Is(err, adapter.ErrAdapterNotFound) {
			sr.Status = "skipped"
			sr.Error = err
			return sr, err
		}
		sr.Status = "failed"
		sr.Error = err
		return sr, err
	}

	logProgress(progressWriter, fmt.Sprintf("[pipeline] starting stage %q (adapter: %s)\n", stage.Name, stage.AdapterID))

	start := time.Now()
	output, runErr := a.Run(ctx, input, cfg, progressWriter)
	sr.Duration = time.Since(start)

	if runErr != nil {
		sr.Status = "failed"
		sr.Error = runErr
		return sr, runErr
	}

	sr.Status = "completed"
	sr.Stats = buildStats(output)

	// Normalise raw findings into finding.Finding values using the per-tool
	// normalizer from the finding package.
	for _, raw := range output.RawFindings {
		sr.rawFindings = append(sr.rawFindings, finding.NormalizeRawFinding(raw))
	}

	// Attach the adapter output for accumulation by the caller.
	sr.adapterOutput = &output

	logProgress(progressWriter, fmt.Sprintf("[pipeline] stage %q completed in %v — %v\n", stage.Name, sr.Duration, sr.Stats))

	return sr, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// stageResultWithFindings extends StageResult with internal fields used only
// during the pipeline run.  The extra fields are not exported so they do not
// leak into the public API.
type stageResultWithFindings struct {
	StageResult
	rawFindings   []finding.Finding
	adapterOutput *adapter.AdapterOutput
}

// mergeOutput merges an adapter's output into the accumulated AdapterInput so
// subsequent stages have access to all previously discovered data.
func mergeOutput(acc adapter.AdapterInput, sr stageResultWithFindings) adapter.AdapterInput {
	if sr.adapterOutput == nil {
		return acc
	}
	out := sr.adapterOutput
	acc.Subdomains = dedup(append(acc.Subdomains, out.Subdomains...))
	acc.LiveHosts = dedup(append(acc.LiveHosts, out.LiveHosts...))
	acc.OpenPorts = dedup(append(acc.OpenPorts, out.OpenPorts...))
	return acc
}

// dedup removes duplicate strings while preserving order.
func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// buildStats produces a simple counter map from adapter output.
func buildStats(out adapter.AdapterOutput) map[string]int {
	return map[string]int{
		"subdomains": len(out.Subdomains),
		"live_hosts": len(out.LiveHosts),
		"open_ports": len(out.OpenPorts),
		"findings":   len(out.RawFindings),
	}
}

// logProgress writes a message to w when w is non-nil.
func logProgress(w io.Writer, msg string) {
	if w != nil {
		_, _ = io.WriteString(w, msg)
	}
}

// effectiveRateLimit returns the rate limit to use for adapter configuration.
// If the caller provides 0 (meaning "use default"), DefaultRateLimit is
// returned.  Any positive value is returned unchanged.
func effectiveRateLimit(configured int) int {
	if configured <= 0 {
		return DefaultRateLimit
	}
	return configured
}
