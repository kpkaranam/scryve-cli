package adapter

import (
	"errors"
	"fmt"
	"sync"
)

// ErrAdapterNotFound is returned by Get when the requested adapter ID has not
// been registered.
var ErrAdapterNotFound = errors.New("adapter not found")

// Registry is a thread-safe map from AdapterID to Adapter.  A single global
// instance (globalRegistry) is provided for convenience; callers that need
// isolation (e.g. tests) can create their own with NewRegistry.
type Registry struct {
	mu       sync.RWMutex
	adapters map[AdapterID]Adapter
}

// NewRegistry constructs and returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[AdapterID]Adapter),
	}
}

// Register adds adapter to the registry.  If an adapter with the same ID is
// already registered it is silently replaced.  Register is safe to call from
// multiple goroutines.
func (r *Registry) Register(a Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[a.ID()] = a
}

// Get returns the adapter registered under id, or ErrAdapterNotFound if no
// such adapter has been registered.
func (r *Registry) Get(id AdapterID) (Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	a, ok := r.adapters[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrAdapterNotFound, id)
	}
	return a, nil
}

// List returns a snapshot of all registered adapters.  The order is not
// guaranteed.
func (r *Registry) List() []Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Adapter, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a)
	}
	return out
}

// MustGet is like Get but panics instead of returning an error.  It is
// intended for init-time wiring where a missing adapter is a programming error
// that should crash the process immediately rather than propagate silently.
func (r *Registry) MustGet(id AdapterID) Adapter {
	a, err := r.Get(id)
	if err != nil {
		panic(fmt.Sprintf("adapter: MustGet(%q): %v", id, err))
	}
	return a
}

// ---------------------------------------------------------------------------
// Package-level global registry
// ---------------------------------------------------------------------------

// globalRegistry is the default shared registry for production code.
var globalRegistry = NewRegistry()

// Register adds adapter to the global registry.
func Register(a Adapter) {
	globalRegistry.Register(a)
}

// Get returns the adapter registered under id in the global registry, or
// ErrAdapterNotFound.
func Get(id AdapterID) (Adapter, error) {
	return globalRegistry.Get(id)
}

// List returns all adapters registered in the global registry.
func List() []Adapter {
	return globalRegistry.List()
}

// MustGet returns the adapter registered under id in the global registry.
// Panics if the adapter is not found.
func MustGet(id AdapterID) Adapter {
	return globalRegistry.MustGet(id)
}

// GetGlobalRegistry returns the global shared registry.
// Use this when you need to pass the registry to pipeline.New().
func GetGlobalRegistry() *Registry {
	return globalRegistry
}
