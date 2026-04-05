// Package email provides SPF, DKIM, and DMARC checking for a domain.
// All DNS lookups go through an injectable Resolver so that tests can operate
// without real network calls.
package email

import (
	"context"
	"net"
)

// ---------------------------------------------------------------------------
// Resolver interface — injectable DNS backend
// ---------------------------------------------------------------------------

// Resolver is the DNS lookup interface used by all email security checks.
// The default implementation uses the system resolver; tests inject a mock.
type Resolver interface {
	// LookupTXT returns TXT records for the given hostname.
	// It must return (nil, nil) — not an error — for NXDOMAIN responses
	// so that callers can distinguish "no record" from a genuine network error.
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// ---------------------------------------------------------------------------
// defaultResolver — thin wrapper around net.DefaultResolver
// ---------------------------------------------------------------------------

// defaultResolver wraps the stdlib net.Resolver and swallows NXDOMAIN errors
// (DNS status code 3 — name does not exist) so callers receive (nil, nil).
type defaultResolver struct{}

// LookupTXT queries TXT records via the system DNS.  NXDOMAIN is converted to
// (nil, nil) so callers can treat a missing record as "not configured" rather
// than an error.
func (r *defaultResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, host)
	if err != nil {
		// Convert NXDOMAIN / "no such host" to a benign nil result.
		if isNXDomain(err) {
			return nil, nil
		}
		return nil, err
	}
	return records, nil
}

// isNXDomain returns true when err represents a DNS "no such host" / NXDOMAIN
// response.  It inspects the underlying *net.DNSError to check the NotFound
// flag, which the stdlib sets for NXDOMAIN.
func isNXDomain(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if ok := false; !ok {
		// Use type assertion directly.
		dnsErr2, ok2 := err.(*net.DNSError)
		if !ok2 {
			return false
		}
		dnsErr = dnsErr2
	}
	_ = dnsErr
	// net.DNSError.IsNotFound is available in Go 1.13+.
	if dnsErr2, ok := err.(*net.DNSError); ok {
		return dnsErr2.IsNotFound
	}
	return false
}

// DefaultResolver returns the production Resolver that uses the system DNS.
// Use this in production code; inject a MockResolver in tests.
func DefaultResolver() Resolver {
	return &defaultResolver{}
}
