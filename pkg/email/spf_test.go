package email_test

import (
	"context"
	"errors"
	"testing"

	"github.com/scryve/scryve/pkg/email"
)

// ---------------------------------------------------------------------------
// CheckSPF — record not found
// ---------------------------------------------------------------------------

func TestCheckSPF_NoRecord(t *testing.T) {
	r := NewMockResolver()
	// No TXT records for example.com → no SPF.
	result := email.CheckSPF(context.Background(), "example.com", r)

	if result.Found {
		t.Error("Found should be false when no SPF record exists")
	}
	if result.Policy != email.SPFPolicyNone {
		t.Errorf("Policy = %q, want %q", result.Policy, email.SPFPolicyNone)
	}
	if result.Error != nil {
		t.Errorf("Error should be nil, got: %v", result.Error)
	}
}

func TestCheckSPF_NonSPFTXTRecordsIgnored(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "google-site-verification=abc123", "MS=ms12345678")

	result := email.CheckSPF(context.Background(), "example.com", r)

	if result.Found {
		t.Error("Found should be false when only non-SPF TXT records exist")
	}
	if result.Policy != email.SPFPolicyNone {
		t.Errorf("Policy = %q, want SPFPolicyNone", result.Policy)
	}
}

// ---------------------------------------------------------------------------
// CheckSPF — record found and parsed
// ---------------------------------------------------------------------------

func TestCheckSPF_StrictPolicy(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 include:_spf.google.com include:sendgrid.net -all")

	result := email.CheckSPF(context.Background(), "example.com", r)

	if !result.Found {
		t.Fatal("Found should be true")
	}
	if result.Policy != email.SPFPolicyFail {
		t.Errorf("Policy = %q, want %q", result.Policy, email.SPFPolicyFail)
	}
	if !result.IsStrict() {
		t.Error("IsStrict() should return true for -all policy")
	}
	if result.IncludeCount != 2 {
		t.Errorf("IncludeCount = %d, want 2", result.IncludeCount)
	}
}

func TestCheckSPF_SoftFailPolicy(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 include:mail.example.com ~all")

	result := email.CheckSPF(context.Background(), "example.com", r)

	if !result.Found {
		t.Fatal("Found should be true")
	}
	if result.Policy != email.SPFPolicySoftFail {
		t.Errorf("Policy = %q, want %q", result.Policy, email.SPFPolicySoftFail)
	}
	if result.IsStrict() {
		t.Error("IsStrict() should return false for ~all policy")
	}
}

func TestCheckSPF_PassPolicy(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 +all")

	result := email.CheckSPF(context.Background(), "example.com", r)

	if result.Policy != email.SPFPolicyPass {
		t.Errorf("Policy = %q, want %q", result.Policy, email.SPFPolicyPass)
	}
	if result.IsStrict() {
		t.Error("IsStrict() should return false for +all policy")
	}
}

func TestCheckSPF_NeutralPolicy(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 ?all")

	result := email.CheckSPF(context.Background(), "example.com", r)

	if result.Policy != email.SPFPolicyNeutral {
		t.Errorf("Policy = %q, want %q", result.Policy, email.SPFPolicyNeutral)
	}
}

func TestCheckSPF_AllWithoutQualifier(t *testing.T) {
	// bare "all" without qualifier is treated as "+all" per RFC 7208 §4.6.2
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 a mx all")

	result := email.CheckSPF(context.Background(), "example.com", r)
	if result.Policy != email.SPFPolicyPass {
		t.Errorf("Policy = %q, want %q (bare 'all' = pass)", result.Policy, email.SPFPolicyPass)
	}
}

func TestCheckSPF_RecordPreserved(t *testing.T) {
	raw := "v=spf1 ip4:192.0.2.0/24 -all"
	r := NewMockResolver()
	r.SetTXT("example.com", raw)

	result := email.CheckSPF(context.Background(), "example.com", r)

	if result.Record != raw {
		t.Errorf("Record = %q, want %q", result.Record, raw)
	}
}

func TestCheckSPF_ZeroIncludes(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 ip4:10.0.0.1 -all")

	result := email.CheckSPF(context.Background(), "example.com", r)

	if result.IncludeCount != 0 {
		t.Errorf("IncludeCount = %d, want 0", result.IncludeCount)
	}
}

// ---------------------------------------------------------------------------
// CheckSPF — DNS error handling
// ---------------------------------------------------------------------------

func TestCheckSPF_DNSError(t *testing.T) {
	r := NewMockResolver()
	r.SetError("example.com", errors.New("network timeout"))

	result := email.CheckSPF(context.Background(), "example.com", r)

	if result.Error == nil {
		t.Error("expected Error to be set on DNS failure")
	}
	if result.Found {
		t.Error("Found should be false on DNS error")
	}
}

// ---------------------------------------------------------------------------
// CheckSPF — case insensitivity
// ---------------------------------------------------------------------------

func TestCheckSPF_CaseInsensitive(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "V=SPF1 -ALL")

	result := email.CheckSPF(context.Background(), "example.com", r)

	if !result.Found {
		t.Error("SPF record should be found regardless of case")
	}
	if result.Policy != email.SPFPolicyFail {
		t.Errorf("Policy = %q, want SPFPolicyFail", result.Policy)
	}
}
