// Package adapter_test contains tests for the adapter interface, registry, and mock adapter.
package adapter_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
)

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

// TestRegistry_RegisterAndGet verifies that a registered adapter can be
// retrieved by its ID.
func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := adapter.NewRegistry()

	mock := &adapter.MockAdapter{MockID: adapter.AdapterIDSubfinder, MockName: "subfinder"}
	reg.Register(mock)

	got, err := reg.Get(adapter.AdapterIDSubfinder)
	if err != nil {
		t.Fatalf("Get(%q) returned unexpected error: %v", adapter.AdapterIDSubfinder, err)
	}
	if got.ID() != adapter.AdapterIDSubfinder {
		t.Errorf("got ID %q, want %q", got.ID(), adapter.AdapterIDSubfinder)
	}
}

// TestRegistry_GetUnknownID verifies that Get returns an error for an
// unregistered adapter ID.
func TestRegistry_GetUnknownID(t *testing.T) {
	reg := adapter.NewRegistry()

	_, err := reg.Get(adapter.AdapterID("nonexistent"))
	if err == nil {
		t.Fatal("Get with unknown ID expected an error, got nil")
	}
	if !errors.Is(err, adapter.ErrAdapterNotFound) {
		t.Errorf("expected ErrAdapterNotFound, got: %v", err)
	}
}

// TestRegistry_List verifies that List returns all registered adapters.
func TestRegistry_List(t *testing.T) {
	reg := adapter.NewRegistry()

	ids := []adapter.AdapterID{
		adapter.AdapterIDSubfinder,
		adapter.AdapterIDHTTPX,
		adapter.AdapterIDNaabu,
	}
	for _, id := range ids {
		reg.Register(&adapter.MockAdapter{MockID: id, MockName: string(id)})
	}

	list := reg.List()
	if len(list) != len(ids) {
		t.Fatalf("List() returned %d adapters, want %d", len(list), len(ids))
	}
}

// TestRegistry_MustGet_Found verifies MustGet returns the adapter when found.
func TestRegistry_MustGet_Found(t *testing.T) {
	reg := adapter.NewRegistry()
	mock := &adapter.MockAdapter{MockID: adapter.AdapterIDNuclei, MockName: "nuclei"}
	reg.Register(mock)

	got := reg.MustGet(adapter.AdapterIDNuclei)
	if got.ID() != adapter.AdapterIDNuclei {
		t.Errorf("MustGet returned ID %q, want %q", got.ID(), adapter.AdapterIDNuclei)
	}
}

// TestRegistry_MustGet_Panics verifies MustGet panics when adapter is not found.
func TestRegistry_MustGet_Panics(t *testing.T) {
	reg := adapter.NewRegistry()

	defer func() {
		if r := recover(); r == nil {
			t.Error("MustGet with unknown ID expected a panic, did not panic")
		}
	}()

	reg.MustGet(adapter.AdapterID("ghost"))
}

// TestRegistry_Register_OverwritesExisting verifies that registering an adapter
// with the same ID replaces the previous entry.
func TestRegistry_Register_OverwritesExisting(t *testing.T) {
	reg := adapter.NewRegistry()

	first := &adapter.MockAdapter{MockID: adapter.AdapterIDSubfinder, MockName: "first"}
	second := &adapter.MockAdapter{MockID: adapter.AdapterIDSubfinder, MockName: "second"}

	reg.Register(first)
	reg.Register(second)

	got, err := reg.Get(adapter.AdapterIDSubfinder)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name() != "second" {
		t.Errorf("expected adapter name %q after overwrite, got %q", "second", got.Name())
	}
}

// ---------------------------------------------------------------------------
// MockAdapter behavior tests
// ---------------------------------------------------------------------------

// TestMockAdapter_Run_ReturnsConfiguredOutput verifies that MockAdapter.Run
// returns the output it was configured with.
func TestMockAdapter_Run_ReturnsConfiguredOutput(t *testing.T) {
	mock := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"api.example.com", "www.example.com"},
		MockLiveHosts:  []string{"https://api.example.com"},
		MockOpenPorts:  []string{"443"},
		MockFindings: []adapter.RawFinding{
			{ToolName: "subfinder", ToolOutput: map[string]interface{}{"host": "api.example.com"}},
		},
	}

	input := adapter.AdapterInput{Domain: "example.com"}
	cfg := adapter.AdapterConfig{RateLimit: 10, Timeout: 5 * time.Second}

	out, err := mock.Run(context.Background(), input, cfg, nil)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	if len(out.Subdomains) != 2 {
		t.Errorf("expected 2 subdomains, got %d", len(out.Subdomains))
	}
	if len(out.LiveHosts) != 1 {
		t.Errorf("expected 1 live host, got %d", len(out.LiveHosts))
	}
	if len(out.OpenPorts) != 1 {
		t.Errorf("expected 1 open port, got %d", len(out.OpenPorts))
	}
	if len(out.RawFindings) != 1 {
		t.Errorf("expected 1 raw finding, got %d", len(out.RawFindings))
	}
	if out.AdapterID != adapter.AdapterIDSubfinder {
		t.Errorf("output AdapterID %q, want %q", out.AdapterID, adapter.AdapterIDSubfinder)
	}
}

// TestMockAdapter_Run_ReturnsConfiguredError verifies that when MockError is
// set, Run returns that error and a zero-value output.
func TestMockAdapter_Run_ReturnsConfiguredError(t *testing.T) {
	want := errors.New("subfinder binary not found")
	mock := &adapter.MockAdapter{
		MockID:    adapter.AdapterIDSubfinder,
		MockName:  "subfinder",
		MockError: want,
	}

	_, err := mock.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, nil)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, want) {
		t.Errorf("expected error %v, got %v", want, err)
	}
}

// TestMockAdapter_Run_RespectsContextCancellation verifies that when a delay is
// configured and the context is canceled, Run returns context.Canceled.
func TestMockAdapter_Run_RespectsContextCancellation(t *testing.T) {
	mock := &adapter.MockAdapter{
		MockID:    adapter.AdapterIDSubfinder,
		MockName:  "subfinder",
		MockDelay: 500 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := mock.Run(ctx, adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, nil)
	if err == nil {
		t.Fatal("expected context cancellation error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("expected context error, got: %v", err)
	}
}

// TestMockAdapter_Check verifies that Check returns a version string when no
// error is configured, and returns the error when one is set.
func TestMockAdapter_Check(t *testing.T) {
	t.Run("returns version when healthy", func(t *testing.T) {
		mock := &adapter.MockAdapter{
			MockID:      adapter.AdapterIDSubfinder,
			MockName:    "subfinder",
			MockVersion: "v2.6.0",
		}
		version, err := mock.Check(context.Background())
		if err != nil {
			t.Fatalf("Check() unexpected error: %v", err)
		}
		if version != "v2.6.0" {
			t.Errorf("expected version %q, got %q", "v2.6.0", version)
		}
	})

	t.Run("returns error when configured", func(t *testing.T) {
		want := errors.New("binary not found")
		mock := &adapter.MockAdapter{
			MockID:         adapter.AdapterIDSubfinder,
			MockName:       "subfinder",
			MockCheckError: want,
		}
		_, err := mock.Check(context.Background())
		if !errors.Is(err, want) {
			t.Errorf("expected %v, got %v", want, err)
		}
	})
}

// TestAdapterIDConstants verifies the AdapterID constants have the expected
// string values used in configuration and logging.
func TestAdapterIDConstants(t *testing.T) {
	cases := []struct {
		id   adapter.AdapterID
		want string
	}{
		{adapter.AdapterIDSubfinder, "subfinder"},
		{adapter.AdapterIDHTTPX, "httpx"},
		{adapter.AdapterIDNaabu, "naabu"},
		{adapter.AdapterIDNuclei, "nuclei"},
		{adapter.AdapterIDEmail, "email"},
	}

	for _, tc := range cases {
		if string(tc.id) != tc.want {
			t.Errorf("AdapterID constant: got %q, want %q", string(tc.id), tc.want)
		}
	}
}

// TestMockAdapter_ProgressWriter_WriteCalled verifies that MockAdapter calls
// the provided progress writer during execution.
func TestMockAdapter_ProgressWriter_WriteCalled(t *testing.T) {
	mock := &adapter.MockAdapter{
		MockID:         adapter.AdapterIDSubfinder,
		MockName:       "subfinder",
		MockSubdomains: []string{"sub.example.com"},
	}

	var buf strings.Builder
	_, err := mock.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected progress writer to receive output, got empty buffer")
	}
}
