package email_test

import (
	"context"
)

// ---------------------------------------------------------------------------
// MockResolver — injectable DNS resolver for tests
// ---------------------------------------------------------------------------

// MockResolver implements the email.Resolver interface by serving responses
// from a pre-populated map. It never makes real network calls.
type MockResolver struct {
	// records maps hostname → list of TXT records to return.
	records map[string][]string

	// errors maps hostname → error to return (takes priority over records).
	errors map[string]error
}

// NewMockResolver returns a MockResolver with no entries.
func NewMockResolver() *MockResolver {
	return &MockResolver{
		records: make(map[string][]string),
		errors:  make(map[string]error),
	}
}

// SetTXT registers a slice of TXT records for host.
func (m *MockResolver) SetTXT(host string, records ...string) {
	m.records[host] = records
}

// SetError registers an error to be returned for host.
func (m *MockResolver) SetError(host string, err error) {
	m.errors[host] = err
}

// LookupTXT returns the pre-configured records or error for host.
// Unknown hosts return (nil, nil) simulating NXDOMAIN.
func (m *MockResolver) LookupTXT(_ context.Context, host string) ([]string, error) {
	if err, ok := m.errors[host]; ok {
		return nil, err
	}
	if recs, ok := m.records[host]; ok {
		return recs, nil
	}
	// NXDOMAIN: return nil, nil (not an error).
	return nil, nil
}
