package adapter

import (
	"context"
	"fmt"
	"io"
	"time"
)

// MockAdapter is a test double that implements the Adapter interface without
// requiring any real binaries.  Configure its fields before passing it to the
// code under test; all fields have zero values that produce benign defaults.
//
// MockAdapter is safe for use in a single goroutine.  It is not safe for
// concurrent use unless the caller serializes access externally.
type MockAdapter struct {
	// MockID is returned by ID(). Defaults to empty string when not set.
	MockID AdapterID

	// MockName is returned by Name(). Defaults to empty string when not set.
	MockName string

	// MockVersion is returned by Check() when MockCheckError is nil.
	// Defaults to "v0.0.0-mock".
	MockVersion string

	// MockCheckError is returned by Check(). When non-nil, Check returns this
	// error and an empty version string.
	MockCheckError error

	// MockSubdomains is included in AdapterOutput.Subdomains on a successful Run.
	MockSubdomains []string

	// MockLiveHosts is included in AdapterOutput.LiveHosts on a successful Run.
	MockLiveHosts []string

	// MockOpenPorts is included in AdapterOutput.OpenPorts on a successful Run.
	MockOpenPorts []string

	// MockFindings is included in AdapterOutput.RawFindings on a successful Run.
	MockFindings []RawFinding

	// MockError is returned by Run when non-nil.  Run still honors context
	// cancellation before returning MockError.
	MockError error

	// MockDelay introduces an artificial delay inside Run.  The delay is
	// implemented via a select so that context cancellation is respected even
	// before the delay elapses.
	MockDelay time.Duration
}

// ID returns the configured MockID.
func (m *MockAdapter) ID() AdapterID {
	return m.MockID
}

// Name returns the configured MockName.
func (m *MockAdapter) Name() string {
	return m.MockName
}

// Check returns the configured MockVersion or MockCheckError.
func (m *MockAdapter) Check(ctx context.Context) (string, error) {
	if m.MockCheckError != nil {
		return "", m.MockCheckError
	}
	version := m.MockVersion
	if version == "" {
		version = "v0.0.0-mock"
	}
	return version, nil
}

// Run simulates a tool execution.
//
// Execution order:
//  1. If MockDelay > 0, block until the delay elapses or ctx is canceled.
//  2. If ctx is canceled (regardless of delay), return ctx.Err().
//  3. If MockError is set, return it.
//  4. Write a progress line to progressWriter (if non-nil).
//  5. Return AdapterOutput populated from the Mock* fields.
func (m *MockAdapter) Run(ctx context.Context, input AdapterInput, cfg AdapterConfig, progressWriter io.Writer) (AdapterOutput, error) {
	// Honor delay with context awareness.
	if m.MockDelay > 0 {
		select {
		case <-time.After(m.MockDelay):
		case <-ctx.Done():
			return AdapterOutput{}, ctx.Err()
		}
	}

	// Check context cancellation even without a delay.
	select {
	case <-ctx.Done():
		return AdapterOutput{}, ctx.Err()
	default:
	}

	// Return the configured error if one is set.
	if m.MockError != nil {
		return AdapterOutput{}, m.MockError
	}

	// Emit a progress message if a writer was provided.
	if progressWriter != nil {
		fmt.Fprintf(progressWriter, "[mock] %s: processing domain %q\n", m.MockName, input.Domain)
	}

	return AdapterOutput{
		AdapterID:   m.MockID,
		RawFindings: m.MockFindings,
		Subdomains:  m.MockSubdomains,
		LiveHosts:   m.MockLiveHosts,
		OpenPorts:   m.MockOpenPorts,
	}, nil
}
