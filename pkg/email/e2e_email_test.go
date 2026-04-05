// E2E tests for email security checks — Story 3.4
package email_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/scryve/scryve/pkg/email"
)

// --------------------------------------------------------------------------
// Mock DNS resolver
// --------------------------------------------------------------------------

type e2eMockResolver struct {
	records map[string][]string
	errs    map[string]error
}

func newMockResolver() *e2eMockResolver {
	return &e2eMockResolver{
		records: make(map[string][]string),
		errs:    make(map[string]error),
	}
}

func (r *e2eMockResolver) LookupTXT(_ context.Context, domain string) ([]string, error) {
	if err, ok := r.errs[domain]; ok {
		return nil, err
	}
	return r.records[domain], nil
}

// --------------------------------------------------------------------------
// SPF tests
// --------------------------------------------------------------------------

func TestE2E_SPF_Strict(t *testing.T) {
	r := newMockResolver()
	r.records["example.com"] = []string{"v=spf1 include:_spf.google.com -all"}
	result := email.CheckSPF(context.Background(), "example.com", r)
	if !result.IsStrict() {
		t.Error("SPF -all should be strict")
	}
}

func TestE2E_SPF_SoftFail(t *testing.T) {
	r := newMockResolver()
	r.records["example.com"] = []string{"v=spf1 ~all"}
	result := email.CheckSPF(context.Background(), "example.com", r)
	if result.IsStrict() {
		t.Error("SPF ~all should NOT be strict")
	}
}

func TestE2E_SPF_Missing(t *testing.T) {
	r := newMockResolver()
	// No records
	result := email.CheckSPF(context.Background(), "example.com", r)
	if result.IsStrict() {
		t.Error("missing SPF should not be strict")
	}
	if result.Record != "" {
		t.Errorf("missing SPF should have empty record, got %q", result.Record)
	}
}

func TestE2E_SPF_MultipleTXTRecords(t *testing.T) {
	r := newMockResolver()
	r.records["example.com"] = []string{
		"google-site-verification=abc123",
		"v=spf1 include:_spf.google.com -all",
		"some-other-record",
	}
	result := email.CheckSPF(context.Background(), "example.com", r)
	if !result.IsStrict() {
		t.Error("should find SPF record among multiple TXT records")
	}
}

// --------------------------------------------------------------------------
// DKIM tests
// --------------------------------------------------------------------------

func TestE2E_DKIM_FoundSelector(t *testing.T) {
	r := newMockResolver()
	r.records["google._domainkey.example.com"] = []string{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN"}
	result := email.CheckDKIM(context.Background(), "example.com", r)

	found := false
	for _, sel := range result.Selectors {
		if sel.Found {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one DKIM selector found")
	}
}

func TestE2E_DKIM_NoSelectors(t *testing.T) {
	r := newMockResolver()
	// No DKIM records
	result := email.CheckDKIM(context.Background(), "example.com", r)

	for _, sel := range result.Selectors {
		if sel.Found {
			t.Errorf("selector %q should not be found", sel.Selector)
		}
	}
}

// --------------------------------------------------------------------------
// DMARC tests
// --------------------------------------------------------------------------

func TestE2E_DMARC_Reject(t *testing.T) {
	r := newMockResolver()
	r.records["_dmarc.example.com"] = []string{"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"}
	result := email.CheckDMARC(context.Background(), "example.com", r)
	if !result.IsEnforced() {
		t.Error("DMARC p=reject should be enforced")
	}
}

func TestE2E_DMARC_Quarantine(t *testing.T) {
	r := newMockResolver()
	r.records["_dmarc.example.com"] = []string{"v=DMARC1; p=quarantine"}
	result := email.CheckDMARC(context.Background(), "example.com", r)
	if !result.IsEnforced() {
		t.Error("DMARC p=quarantine should be enforced")
	}
}

func TestE2E_DMARC_None(t *testing.T) {
	r := newMockResolver()
	r.records["_dmarc.example.com"] = []string{"v=DMARC1; p=none"}
	result := email.CheckDMARC(context.Background(), "example.com", r)
	if result.IsEnforced() {
		t.Error("DMARC p=none should NOT be enforced")
	}
}

func TestE2E_DMARC_Missing(t *testing.T) {
	r := newMockResolver()
	result := email.CheckDMARC(context.Background(), "example.com", r)
	if result.IsEnforced() {
		t.Error("missing DMARC should not be enforced")
	}
}

// --------------------------------------------------------------------------
// Full CheckDomain
// --------------------------------------------------------------------------

func TestE2E_CheckDomain_AllChecks(t *testing.T) {
	r := newMockResolver()
	r.records["example.com"] = []string{"v=spf1 -all"}
	r.records["google._domainkey.example.com"] = []string{"v=DKIM1; k=rsa; p=abc"}
	r.records["_dmarc.example.com"] = []string{"v=DMARC1; p=reject"}

	result := email.CheckDomain(context.Background(), "example.com", r)
	if result.Domain != "example.com" {
		t.Errorf("domain = %q", result.Domain)
	}
	if !result.SPF.IsStrict() {
		t.Error("SPF should be strict")
	}
	if !result.DMARC.IsEnforced() {
		t.Error("DMARC should be enforced")
	}
}

func TestE2E_CheckDomain_DNSError(t *testing.T) {
	r := newMockResolver()
	r.errs["example.com"] = fmt.Errorf("DNS timeout")
	r.errs["_dmarc.example.com"] = fmt.Errorf("DNS timeout")

	// Should not panic — handle DNS errors gracefully
	result := email.CheckDomain(context.Background(), "example.com", r)
	if result.Domain != "example.com" {
		t.Errorf("domain should still be set even on DNS error")
	}
}
