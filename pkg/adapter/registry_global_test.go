package adapter_test

// Tests for the package-level (global) registry functions: Register, Get, List,
// and MustGet. These wrap globalRegistry and are distinct from the per-instance
// Registry methods tested in adapter_test.go.

import (
	"errors"
	"testing"

	"github.com/scryve/scryve/pkg/adapter"
)

// TestGlobalRegistry_GetRegistered verifies that Get on the global registry
// returns an adapter that was registered via the package-level Register function.
// The subfinder adapter registers itself in its init() function so it must be
// present when this test runs.
func TestGlobalRegistry_GetRegistered(t *testing.T) {
	// SubfinderAdapter registers itself during package init; it must be present.
	a, err := adapter.Get(adapter.AdapterIDSubfinder)
	if err != nil {
		t.Fatalf("adapter.Get(%q) unexpected error: %v", adapter.AdapterIDSubfinder, err)
	}
	if a.ID() != adapter.AdapterIDSubfinder {
		t.Errorf("returned adapter ID = %q, want %q", a.ID(), adapter.AdapterIDSubfinder)
	}
}

// TestGlobalRegistry_GetUnknown verifies that Get returns ErrAdapterNotFound for
// an ID that is not in the global registry.
func TestGlobalRegistry_GetUnknown(t *testing.T) {
	_, err := adapter.Get(adapter.AdapterID("definitely-not-registered-xyz-abc"))
	if err == nil {
		t.Fatal("expected ErrAdapterNotFound, got nil")
	}
	if !errors.Is(err, adapter.ErrAdapterNotFound) {
		t.Errorf("expected ErrAdapterNotFound, got: %v", err)
	}
}

// TestGlobalRegistry_List verifies that the global List returns at least the
// adapters that have been registered via init() side-effects (at minimum subfinder).
func TestGlobalRegistry_List(t *testing.T) {
	all := adapter.List()
	if len(all) == 0 {
		t.Fatal("adapter.List() returned empty slice; at least subfinder should be registered via init()")
	}

	// Verify that every adapter returned has a non-empty ID and Name.
	for _, a := range all {
		if a.ID() == "" {
			t.Error("adapter.List() returned an adapter with empty ID")
		}
		if a.Name() == "" {
			t.Error("adapter.List() returned an adapter with empty Name")
		}
	}
}

// TestGlobalRegistry_MustGet_Found verifies that MustGet returns the expected
// adapter without panicking when the ID exists.
func TestGlobalRegistry_MustGet_Found(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("MustGet panicked unexpectedly: %v", r)
		}
	}()

	a := adapter.MustGet(adapter.AdapterIDSubfinder)
	if a.ID() != adapter.AdapterIDSubfinder {
		t.Errorf("MustGet returned ID %q, want %q", a.ID(), adapter.AdapterIDSubfinder)
	}
}

// TestGlobalRegistry_MustGet_Panics verifies that the global MustGet panics when
// the adapter ID is not registered.
func TestGlobalRegistry_MustGet_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected MustGet to panic for unknown ID, did not panic")
		}
	}()

	adapter.MustGet(adapter.AdapterID("will-never-be-registered-zzz"))
}
